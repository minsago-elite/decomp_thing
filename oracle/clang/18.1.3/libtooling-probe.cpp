#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclTemplate.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Type.h"
#include "clang/Basic/FileManager.h"
#include "clang/Basic/LangOptions.h"
#include "clang/Basic/Specifiers.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Lex/Lexer.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Config/llvm-config.h"

#include <array>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace clang;

static const char *callingConventionName(CallingConv convention) {
  switch (convention) {
  case CC_C: return "CC_C";
  case CC_X86StdCall: return "CC_X86StdCall";
  case CC_X86FastCall: return "CC_X86FastCall";
  case CC_X86ThisCall: return "CC_X86ThisCall";
  case CC_X86VectorCall: return "CC_X86VectorCall";
  case CC_X86Pascal: return "CC_X86Pascal";
  case CC_Win64: return "CC_Win64";
  case CC_X86_64SysV: return "CC_X86_64SysV";
  case CC_X86RegCall: return "CC_X86RegCall";
  case CC_AAPCS: return "CC_AAPCS";
  case CC_AAPCS_VFP: return "CC_AAPCS_VFP";
  case CC_IntelOclBicc: return "CC_IntelOclBicc";
  case CC_SpirFunction: return "CC_SpirFunction";
  case CC_OpenCLKernel: return "CC_OpenCLKernel";
  case CC_Swift: return "CC_Swift";
  case CC_SwiftAsync: return "CC_SwiftAsync";
  case CC_PreserveMost: return "CC_PreserveMost";
  case CC_PreserveAll: return "CC_PreserveAll";
  case CC_AArch64VectorCall: return "CC_AArch64VectorCall";
  case CC_AArch64SVEPCS: return "CC_AArch64SVEPCS";
  case CC_AMDGPUKernelCall: return "CC_AMDGPUKernelCall";
  case CC_M68kRTD: return "CC_M68kRTD";
  }
  return nullptr;
}

static const std::array<CallingConv, 22> CallingConventions = {
    CC_C, CC_X86StdCall, CC_X86FastCall, CC_X86ThisCall, CC_X86VectorCall,
    CC_X86Pascal, CC_Win64, CC_X86_64SysV, CC_X86RegCall, CC_AAPCS,
    CC_AAPCS_VFP, CC_IntelOclBicc, CC_SpirFunction, CC_OpenCLKernel, CC_Swift,
    CC_SwiftAsync, CC_PreserveMost, CC_PreserveAll, CC_AArch64VectorCall,
    CC_AArch64SVEPCS, CC_AMDGPUKernelCall, CC_M68kRTD};

class ApiVisitor : public RecursiveASTVisitor<ApiVisitor> {
public:
  bool VisitFunctionDecl(FunctionDecl *decl) {
    (void)decl->getPrimaryTemplate();
    (void)decl->getTemplateSpecializationKind();
    if (const auto *type = decl->getType()->getAs<FunctionProtoType>()) {
      (void)type->getParamTypes();
      (void)type->getCallConv();
      (void)type->getExceptionSpecType();
      (void)callingConventionName(type->getCallConv());
    }
    return true;
  }

  bool VisitClassTemplateSpecializationDecl(ClassTemplateSpecializationDecl *decl) {
    (void)decl->getSpecializedTemplateOrPartial();
    (void)decl->getTemplateArgs().asArray();
    (void)decl->getTemplateInstantiationArgs();
    return true;
  }

  bool VisitClassTemplatePartialSpecializationDecl(
      ClassTemplatePartialSpecializationDecl *decl) {
    (void)decl->getTemplateParameters()->asArray();
    (void)decl->getSpecializedTemplate();
    return true;
  }

  bool VisitVarDecl(VarDecl *decl) {
    QualType canonical = decl->getType().getCanonicalType();
    (void)canonical.getSplitUnqualifiedType();
    return true;
  }
};

class ProbeConsumer : public ASTConsumer {
public:
  explicit ProbeConsumer(CompilerInstance &compiler) : compiler(compiler) {}

  void HandleTranslationUnit(ASTContext &context) override {
    const LangOptions &options = compiler.getLangOpts();
    if (options.CPlusPlus14)
      runtimeLangOptionsChecks.emplace_back("LangOptions::CPlusPlus14=true");
    if (!options.CPlusPlus20)
      runtimeLangOptionsChecks.emplace_back("LangOptions::CPlusPlus20=false");
    if (options.DoubleSquareBracketAttributes)
      runtimeLangOptionsChecks.emplace_back("LangOptions::DoubleSquareBracketAttributes=true");
    if (options.Trigraphs)
      runtimeLangOptionsChecks.emplace_back("LangOptions::Trigraphs=true");
    if (runtimeLangOptionsChecks.size() != 4)
      failed = true;
    targetTriple = compiler.getTarget().getTriple().str();
    if (targetTriple != "x86_64-pc-linux-gnu")
      failed = true;
    ApiVisitor visitor;
    visitor.TraverseDecl(context.getTranslationUnitDecl());
    const SourceManager &sources = context.getSourceManager();
    (void)Lexer::getLocForEndOfToken(sources.getLocForEndOfFile(sources.getMainFileID()),
                                     0, sources, context.getLangOpts());
  }

  bool failed = false;
  std::string targetTriple;
  std::vector<std::string> runtimeLangOptionsChecks;

private:
  CompilerInstance &compiler;
};

struct MacroObservations {
  unsigned expansionCount = 0;
  unsigned macroInfoChecks = 0;
  unsigned nonBuiltinClassifications = 0;
};

class MacroCallbackProbe : public PPCallbacks {
public:
  explicit MacroCallbackProbe(MacroObservations &observations)
      : observations(observations) {}

  void MacroExpands(const Token &, const MacroDefinition &definition, SourceRange,
                    const MacroArgs *) override {
    ++observations.expansionCount;
    if (const MacroInfo *info = definition.getMacroInfo())
      if (!info->isBuiltinMacro()) {
        ++observations.macroInfoChecks;
        ++observations.nonBuiltinClassifications;
      } else {
        ++observations.macroInfoChecks;
      }
  }

private:
  MacroObservations &observations;
};

class ProbeAction : public ASTFrontendAction {
public:
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &compiler,
                                                 StringRef) override {
    auto consumer = std::make_unique<ProbeConsumer>(compiler);
    consumerView = consumer.get();
    return consumer;
  }

  bool BeginSourceFileAction(CompilerInstance &compiler) override {
    (void)compiler.getPreprocessor().getLangOpts();
    compiler.getPreprocessor().addPPCallbacks(
        std::make_unique<MacroCallbackProbe>(macroObservations));
    return true;
  }

  void EndSourceFileAction() override {
    if (consumerView && consumerView->failed)
      failed = true;
    if (consumerView) {
      targetTriple = consumerView->targetTriple;
      runtimeLangOptionsChecks = consumerView->runtimeLangOptionsChecks;
    }
    if (macroObservations.expansionCount == 0 ||
        macroObservations.macroInfoChecks == 0 ||
        macroObservations.nonBuiltinClassifications == 0)
      failed = true;
  }

  bool failed = false;
  std::string targetTriple;
  MacroObservations macroObservations;
  std::vector<std::string> runtimeLangOptionsChecks;

private:
  ProbeConsumer *consumerView = nullptr;
};

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: libtooling-probe <cxx14-fixture>\n";
    return 2;
  }
  std::vector<std::string> names;
  for (CallingConv convention : CallingConventions) {
    const char *name = callingConventionName(convention);
    if (!name) {
      std::cerr << "unmapped calling convention\n";
      return 3;
    }
    names.emplace_back(name);
  }

  FileSystemOptions filesystemOptions;
  FileManager files(filesystemOptions);
  std::vector<std::string> command = {
      "clang++-18", "--no-default-config", "-std=c++14", "-fsyntax-only", argv[1]};
  auto action = std::make_unique<ProbeAction>();
  ProbeAction *actionView = action.get();
  tooling::ToolInvocation invocation(std::move(command), std::move(action), &files);
  if (!invocation.run() || actionView->failed)
    return 4;

  std::cout << "{\"compilerVersion\":\"" << getClangVersion()
            << "\",\"target\":\"" << actionView->targetTriple
            << "\",\"runtimeLangOptionsChecks\":[";
  for (std::size_t i = 0; i < actionView->runtimeLangOptionsChecks.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << '\"' << actionView->runtimeLangOptionsChecks[i] << '\"';
  }
  std::cout << "],\"macroObservations\":{\"expansionCount\":"
            << actionView->macroObservations.expansionCount
            << ",\"macroInfoChecks\":" << actionView->macroObservations.macroInfoChecks
            << ",\"nonBuiltinClassifications\":"
            << actionView->macroObservations.nonBuiltinClassifications
            << "},\"callingConventions\":[";
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << '\"' << names[i] << '\"';
  }
  std::cout << "],\"apiChecks\":["
               "\"ClassTemplatePartialSpecializationDecl::getSpecializedTemplate\","
               "\"ClassTemplatePartialSpecializationDecl::getTemplateParameters\","
               "\"ClassTemplateSpecializationDecl::getSpecializedTemplateOrPartial\","
               "\"ClassTemplateSpecializationDecl::getTemplateArgs\","
               "\"ClassTemplateSpecializationDecl::getTemplateInstantiationArgs\","
               "\"CompilerInstance::getTarget\","
               "\"FunctionDecl::getPrimaryTemplate\","
               "\"FunctionDecl::getTemplateSpecializationKind\","
               "\"FunctionProtoType::getCallConv\","
               "\"FunctionProtoType::getExceptionSpecType\","
               "\"FunctionProtoType::getParamTypes\","
               "\"LangOptions::CPlusPlus14\","
               "\"LangOptions::DoubleSquareBracketAttributes\","
               "\"LangOptions::Trigraphs\","
               "\"Lexer::getLocForEndOfToken\","
               "\"MacroInfo::isBuiltinMacro\","
               "\"PPCallbacks::MacroExpands\","
               "\"Preprocessor::getLangOpts\","
               "\"QualType::getCanonicalType\","
               "\"QualType::getSplitUnqualifiedType\","
               "\"TargetInfo::getTriple\","
               "\"ToolInvocation\"]}\n";
  return 0;
}
