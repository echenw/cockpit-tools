import assert from 'node:assert/strict';
import test from 'node:test';
import { loadHookModule } from '../../tests/helpers/reactHookHarness';

function nodes(tree: any): any[] {
  if (!tree || typeof tree !== 'object') return [];
  if (Array.isArray(tree)) return tree.flatMap(nodes);
  return [tree, ...nodes(tree.props?.children)];
}

function text(tree: any): string {
  if (tree == null || typeof tree === 'boolean') return '';
  if (Array.isArray(tree)) return tree.map(text).join('');
  return typeof tree === 'object' ? text(tree.props?.children) : String(tree);
}

test('action results update mounted live regions without moving focus', () => {
  const target = {
    contains: () => false,
    getBoundingClientRect: () => ({ left: 100, top: 100, bottom: 130, width: 30, height: 30 }),
  };
  const document = { body: {}, activeElement: target, contains: () => true,
    addEventListener() {}, removeEventListener() {} };
  const h = loadHookModule(new URL('./ActionBubble.tsx', import.meta.url), {
    'react-dom': { createPortal: (tree: unknown) => tree },
    'react-i18next': { useTranslation: () => ({ t: (_key: string, fallback: string) => fallback }) },
  }, { document, window: {
    innerWidth: 900,
    setTimeout: () => 1, clearTimeout() {}, requestAnimationFrame: () => 1, cancelAnimationFrame() {},
    addEventListener() {}, removeEventListener() {},
  } });
  let api = h.render(() => h.exports.useActionBubble());
  const liveRegions = () => nodes(api.renderBubble()).filter((node) => ['status', 'alert'].includes(node.props?.role));
  assert.deepEqual(liveRegions().map((node) => node.props.role), ['status', 'alert'],
    'empty live regions must exist before the first result');

  for (const tone of ['success', 'info', 'error'] as const) {
    api.showBubble(target, `result-${tone}`, tone);
    api = h.flush();
    const [status, alert] = liveRegions();
    assert.equal(status.props['aria-atomic'], 'true');
    assert.equal(alert.props['aria-atomic'], 'true');
    assert.equal(text(status), tone === 'error' ? '' : `result-${tone}`);
    assert.equal(text(alert), tone === 'error' ? `result-${tone}` : '');
    assert.equal(document.activeElement, target);
    api.closeBubble();
    api = h.flush();
    assert.deepEqual(liveRegions().map(text), ['', ''], 'closing clears content and retains both regions');
  }
  h.unmount();
});
