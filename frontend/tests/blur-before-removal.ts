/**
 * Models Chrome removing a focused node: it dispatches blur while the node is still connected, then removes it.
 * jsdom removes focus silently, so tests that must tell a removal blur from a reader's blur install this.
 * Returns the restore function.
 */
export function blurBeforeRemoval(): () => void {
  const removeChild = Reflect.get(Node.prototype, 'removeChild') as (this: Node, child: Node) => Node;
  const remove = Reflect.get(Element.prototype, 'remove');
  const blurInside = (node: Node) => {
    const active = document.activeElement;
    if (active instanceof HTMLElement && node.contains(active)) active.blur();
  };
  Reflect.set(Node.prototype, 'removeChild', function (this: Node, child: Node) { blurInside(child); return removeChild.call(this, child); });
  Reflect.set(Element.prototype, 'remove', function (this: Element) { blurInside(this); remove.call(this); });
  return () => { Reflect.set(Node.prototype, 'removeChild', removeChild); Reflect.set(Element.prototype, 'remove', remove); };
}
