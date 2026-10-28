// V2 bounded interface projection. Record identity/layout originate in one ASTContext.
#include "clang/AST/ASTContext.h"
#include "clang/AST/Attr.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecordLayout.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <map>
#include <set>
#include <functional>
using namespace clang;
using llvm::json::Object;
using llvm::json::Array;
using llvm::json::Value;
namespace {
// The same active traversal guard is exercised by synthetic unresolved/cycle fixtures.
struct ResolutionStack {
 std::set<const void*> entries;
 bool enter(const void *node){return entries.insert(node).second;}
 void leave(const void *node){entries.erase(node);}
};
struct Probe {
 ASTContext &c; Array diagnostics, provenance, gccBindings; unsigned nodes=0;
 std::map<const Decl*,unsigned> ids; ResolutionStack active;
 bool refused=false;
 explicit Probe(ASTContext &ctx):c(ctx){}
 Value reject(llvm::StringRef code) { refused=true; diagnostics.push_back(code.str()); return Object{{"kind","unsupported"},{"reason",code.str()}}; }
 unsigned id(const Decl *d) { d=d->getCanonicalDecl(); auto [i,ok]=ids.emplace(d,ids.size()+1); return i->second; }
 bool attrs(const Decl *d) {
  for(const auto *a:d->attrs()) if(!(isa<VisibilityAttr>(a) && (isa<FunctionDecl>(d) || isa<VarDecl>(d)))) { reject("unsupported-reachable-declaration-attribute:"+std::string(a->getSpelling()));return false; }
  return true;
 }
 Value type(QualType q, unsigned depth=0) {
  if(++nodes>4096 || depth>64) return reject("graph-bound");
  if(q.isNull())return reject("unresolved-type");
  unsigned quals=q.getLocalQualifiers().getAsOpaqueValue();
  const Type *t=q.getTypePtr();
  if(!active.enter(t))return reject("type-resolution-cycle");
  struct Pop { ResolutionStack&s;const Type*t;~Pop(){s.leave(t);} } pop{active,t};
  if(const auto *td=dyn_cast<TypedefType>(t)) {
   const auto *d=td->getDecl(); attrs(d);
   Object edge{{"kind","alias"},{"identity",id(d)},{"name",d->getNameAsString()},{"underlyingDiagnosticSpelling",d->getUnderlyingType().getAsString()}};
   const Type *ut=d->getUnderlyingType().getTypePtr();
   if(auto *alias=dyn_cast<TypedefType>(ut))edge["targetIdentity"]=id(alias->getDecl());
   else if(auto *record=ut->getAs<RecordType>())edge["targetIdentity"]=id(record->getDecl());
   else if(auto *en=ut->getAs<EnumType>())edge["targetIdentity"]=id(en->getDecl());
   provenance.push_back(std::move(edge));
   auto desc=type(d->getUnderlyingType().withCVRQualifiers(q.getCVRQualifiers()),depth+1);
   if(d->getDeclContext()->isTranslationUnit()) gccBindings.push_back(Object{{"expression",d->getNameAsString()},{"descriptor",desc}});
   return desc;
  }
  if(isa<ParenType>(t))return type(q.getSingleStepDesugaredType(c),depth+1);
  if(isa<AttributedType>(t))return reject("unsupported-attributed-type");
  if(t->isVoidType())return Object{{"kind","void"},{"qualifiers",quals}};
  if(const auto *b=dyn_cast<BuiltinType>(t)) {
   if(b->isInteger())return Object{{"kind","integer"},{"bits",c.getTypeSize(q)},{"signed",t->isSignedIntegerType()},{"qualifiers",quals}};
   if(b->isFloatingPoint() && (b->getKind()==BuiltinType::Float || b->getKind()==BuiltinType::Double || b->getKind()==BuiltinType::LongDouble))
    return Object{{"kind","float"},{"name",b->getName(c.getPrintingPolicy()).str()},{"bits",c.getTypeSize(q)},{"qualifiers",quals}};
   return reject("unsupported-builtin-type");
  }
  if(const auto *p=dyn_cast<PointerType>(t)) {
   QualType pt=p->getPointeeType();
   if(!pt->isVoidType() && !pt->isFunctionProtoType())return reject("unsupported-pointer-pointee-contract");
   return Object{{"kind","pointer"},{"bits",c.getTypeSize(q)},{"qualifiers",quals},{"pointee",type(pt,depth+1)}};
  }
  if(const auto *f=dyn_cast<FunctionProtoType>(t)) {
   if(f->getCallConv()!=CC_C)return reject("unsupported-calling-convention");
   if(f->hasExtParameterInfos())return reject("unsupported-function-parameter-attributes");
   Array params;for(auto p:f->param_types())params.push_back(type(p,depth+1));
   return Object{{"kind","function"},{"return",type(f->getReturnType(),depth+1)},{"parameters",std::move(params)},{"variadic",f->isVariadic()},{"callingConvention","C"}};
  }
  if(isa<FunctionNoProtoType>(t))return reject("nonprototype-function");
  if(const auto *r=dyn_cast<RecordType>(t)) {
   const auto *canonical=cast<RecordDecl>(r->getDecl()->getCanonicalDecl());const auto *d=canonical->getDefinition();
   if(!d)return reject("incomplete-by-value-record");
   attrs(canonical);attrs(d);
   if(d->isUnion())return reject("unsupported-union");
   const auto &layout=c.getASTRecordLayout(d);Array fields, fieldIds;unsigned index=0;
   for(const auto *field:d->fields()) {
    attrs(field);if(field->isBitField())return reject("unsupported-bitfield");
    if(field->isAnonymousStructOrUnion())return reject("unsupported-anonymous-field");
    fields.push_back(Object{{"name",field->getNameAsString()},{"type",type(field->getType(),depth+1)},{"offsetBits",layout.getFieldOffset(index++)}});
    fieldIds.push_back(Object{{"identity",id(field)},{"name",field->getNameAsString()}});
   }
   provenance.push_back(Object{{"kind","record"},{"identity",id(canonical)},{"definitionIdentity",id(d)},{"diagnosticName",d->getNameAsString()},{"fields",std::move(fieldIds)}});
   Object desc{{"kind","record"},{"sizeBits",uint64_t(layout.getSize().getQuantity()*c.getCharWidth())},{"alignBits",uint64_t(layout.getAlignment().getQuantity()*c.getCharWidth())},{"qualifiers",quals},{"fields",std::move(fields)}};
   if(!d->getName().empty() && d->getDeclContext()->isTranslationUnit()) gccBindings.push_back(Object{{"expression","struct "+d->getNameAsString()},{"descriptor",Value(Object(desc))}});
   return desc;
  }
  if(const auto *e=dyn_cast<EnumType>(t)) {
   const auto *d=e->getDecl()->getDefinition();if(!d)return reject("incomplete-enum");attrs(d);Array values;
   for(auto *v:d->enumerators()){attrs(v);llvm::SmallString<32> s;v->getInitVal().toString(s,10);values.push_back(Object{{"name",v->getNameAsString()},{"value",s.str().str()}});}
   provenance.push_back(Object{{"kind","enum"},{"identity",id(d)},{"name",d->getNameAsString()}});
   Object desc{{"kind","enum"},{"qualifiers",quals},{"integerType",type(d->getIntegerType(),depth+1)},{"values",std::move(values)}};
   if(!d->getName().empty() && d->getDeclContext()->isTranslationUnit()) gccBindings.push_back(Object{{"expression","enum "+d->getNameAsString()},{"descriptor",Value(Object(desc))}});
   return desc;
  }
  return reject("unsupported-type-class:"+std::string(t->getTypeClassName()));
 }
 Object run() {
  Object interfaces;std::set<std::string> required={"acp_mix","acp_pair_scale","acp_update","acp_apply","acp_fold","acp_state"};
  std::map<std::string,const ValueDecl*> found;
  for(auto *d:c.getTranslationUnitDecl()->decls())if(auto *v=dyn_cast<ValueDecl>(d)) {
   std::string name=v->getNameAsString();if(!required.count(name))continue;
   if(!isa<FunctionDecl>(v)&&!isa<VarDecl>(v)){reject("required-symbol-wrong-declaration-kind");continue;}
   attrs(v);if(auto *f=dyn_cast<FunctionDecl>(v))for(auto *p:f->parameters())attrs(p);
   if(found.count(name)&&found[name]->getCanonicalDecl()!=v->getCanonicalDecl())reject("ambiguous-required-redeclaration");
   found[name]=v;
  }
  for(const auto &name:required){if(!found.count(name)){reject("missing-required-declaration:"+name);continue;}interfaces[name]=type(found[name]->getType());}
  return Object{{"schemaVersion",2},{"target",c.getTargetInfo().getTriple().str()},{"dataLayout",std::string(c.getTargetInfo().getDataLayoutString())},{"status",refused?"refused":"supported"},{"diagnostics",std::move(diagnostics)},{"interfaces",std::move(interfaces)},{"provenance",std::move(provenance)},{"gccTypeBindings",std::move(gccBindings)}};
 }
};
struct Consumer:ASTConsumer { Object &out;explicit Consumer(Object&o):out(o){} void HandleTranslationUnit(ASTContext &c) override{out=Probe(c).run();} };
struct Action:ASTFrontendAction { Object &out;explicit Action(Object&o):out(o){} std::unique_ptr<ASTConsumer>CreateASTConsumer(CompilerInstance&,llvm::StringRef)override{return std::make_unique<Consumer>(out);} };
}
int resolverFixture(llvm::StringRef path) {
 auto buffer=llvm::MemoryBuffer::getFile(path);
 if(!buffer || (*buffer)->getBufferSize()>262144)return 64;
 auto parsed=llvm::json::parse((*buffer)->getBuffer());if(!parsed)return 64;
 auto *root=parsed->getAsObject();if(!root)return 64;
 auto *nodes=root->getArray("nodes");auto start=root->getString("root");if(!nodes || !start)return 64;
 std::map<std::string,const Object*> lookup;
 for(const auto &v:*nodes){auto *n=v.getAsObject();if(!n)return 64;auto name=n->getString("id");if(!name || !lookup.emplace(name->str(),n).second)return 64;}
 ResolutionStack active;unsigned visited=0;std::string diagnostic;
 std::function<bool(std::string,unsigned)> visit=[&](std::string name,unsigned depth){
  if(++visited>4096 || depth>64){diagnostic="graph-bound";return false;}
  auto found=lookup.find(name);if(found==lookup.end()){diagnostic="unresolved-identity";return false;}
  auto *node=found->second;
  if(!active.enter(node)){diagnostic="type-resolution-cycle";return false;}
  bool ok=true;if(auto target=node->getString("target"))ok=visit(target->str(),depth+1);
  active.leave(node);return ok;
 };
 bool ok=visit(start->str(),0);
 llvm::outs()<<llvm::formatv("{0:2}\n",Value(Object{{"schemaVersion",2},{"fixtureOnly",true},{"status",ok?"supported":"refused"},{"diagnostic",diagnostic},{"visited",visited}}));return ok?0:2;
}
int main(int argc,char**argv) {
 if(argc==3 && llvm::StringRef(argv[1])=="--resolver-fixture")return resolverFixture(argv[2]);
 if(argc!=2){llvm::errs()<<"usage: record_identity_probe SOURCE\n";return 64;}
 auto input=llvm::MemoryBuffer::getFile(argv[1]);if(!input){llvm::errs()<<"source-read-failed\n";return 1;}
 if((*input)->getBufferSize()>262144){llvm::errs()<<"source-bound\n";return 1;}
 Object out;
 bool ok=tooling::runToolOnCodeWithArgs(std::make_unique<Action>(out),(*input)->getBuffer(),{"-std=c11","-target","x86_64-unknown-linux-gnu","-fno-color-diagnostics"},argv[1],"/usr/lib/llvm/23/bin/clang");
 if(!ok){llvm::outs()<<"{\"schemaVersion\":2,\"status\":\"refused\",\"diagnostics\":[\"syntax-failure\"]}\n";return 1;}
 bool refused=out.getString("status")=="refused";llvm::outs()<<llvm::formatv("{0:2}\n",Value(std::move(out)));return refused?2:0;
}
