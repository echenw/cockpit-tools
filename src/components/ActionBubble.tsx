import { useState, useCallback, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { Check, AlertCircle, Info, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import './ActionBubble.css';

export type ActionBubbleTone = 'success' | 'error' | 'info';

export interface ActionBubbleState {
  target: HTMLElement;
  text: string;
  tone: ActionBubbleTone;
  id: number;
}

interface PositionState {
  top: number;
  left: number;
  width: number;
  height: number;
  arrowX: number;
  placement: 'top' | 'bottom';
}

export function useActionBubble() {
  const { t } = useTranslation();
  const [bubble, setBubble] = useState<ActionBubbleState | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<number | null>(null);
  const idSeqRef = useRef(0);

  useEffect(() => () => {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current);
  }, []);

  const showBubble = useCallback(
    (
      target: HTMLElement | string | null | undefined,
      text: string,
      tone: ActionBubbleTone = 'success'
    ) => {
      if (!target) return;
      const el = typeof target === 'string' ? document.getElementById(target) : target;
      if (!el) return;

      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }

      const nextId = ++idSeqRef.current;
      setBubble({
        target: el,
        text,
        tone,
        id: nextId,
      });

      // 成功与提示显示 2.8 秒，错误信息显示 4.5 秒便于阅读完整内容
      const duration = tone === 'error' ? 4500 : 2800;
      const timeoutId = window.setTimeout(() => {
        setBubble((prev) => (prev?.id === nextId ? null : prev));
        if (timerRef.current === timeoutId) timerRef.current = null;
      }, duration);
      timerRef.current = timeoutId;
    },
    []
  );

  const closeBubble = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setBubble(null);
  }, []);

  const [pos, setPos] = useState<PositionState | null>(null);

  const updatePos = useCallback(() => {
    if (!bubble?.target) return;
    if (!document.contains(bubble.target)) {
      closeBubble();
      return;
    }
    const rect = bubble.target.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) {
      closeBubble();
      return;
    }

    const contentEl = contentRef.current;
    const width = contentEl ? Math.round(contentEl.offsetWidth) : 160;
    const height = contentEl ? Math.round(contentEl.offsetHeight) : 36;

    const anchorCenter = rect.left + rect.width / 2;
    let left = anchorCenter - width / 2;
    const minLeft = 12;
    const maxLeft = Math.max(minLeft, window.innerWidth - width - 12);
    left = Math.max(minLeft, Math.min(maxLeft, left));

    const arrowX = Math.round(Math.max(20, Math.min(width - 20, anchorCenter - left)));

    let placement: 'top' | 'bottom' = 'top';
    const totalHeight = height + 6;
    let top = rect.top - totalHeight - 6;
    if (rect.top < 64 || top < 10) {
      placement = 'bottom';
      top = rect.bottom + 6;
    }

    setPos({
      top: Math.round(top),
      left: Math.round(left),
      width,
      height,
      arrowX,
      placement,
    });
  }, [bubble, closeBubble]);

  useEffect(() => {
    if (!bubble) {
      setPos(null);
      return;
    }
    updatePos();
    const rafId = window.requestAnimationFrame(() => {
      updatePos();
    });
    window.addEventListener('resize', updatePos);
    window.addEventListener('scroll', updatePos, true);
    return () => {
      window.cancelAnimationFrame(rafId);
      window.removeEventListener('resize', updatePos);
      window.removeEventListener('scroll', updatePos, true);
    };
  }, [bubble, updatePos]);

  useEffect(() => {
    if (!bubble) return;
    const handlePointerDown = (e: MouseEvent) => {
      if (containerRef.current?.contains(e.target as Node)) return;
      if (bubble.target.contains(e.target as Node)) return;
      closeBubble();
    };
    const timer = window.setTimeout(() => {
      document.addEventListener('pointerdown', handlePointerDown);
    }, 40);
    return () => {
      window.clearTimeout(timer);
      document.removeEventListener('pointerdown', handlePointerDown);
    };
  }, [bubble, closeBubble]);

  const renderBubble = () => {
    if (!bubble) return null;

    const r = 9;
    const w = pos?.width ?? 160;
    const h = pos?.height ?? 36;
    const ax = pos?.arrowX ?? 80;
    const placement = pos?.placement ?? 'top';

    // 生成单条连续闭合的 SVG Path：气泡主体与小箭头由同一根线条闭合绘制，物理上绝无任何拼接缝隙或割裂线
    let pathD = '';
    if (placement === 'top') {
      pathD = [
        `M ${r},0`,
        `H ${w - r}`,
        `A ${r},${r} 0 0 1 ${w},${r}`,
        `V ${h - r}`,
        `A ${r},${r} 0 0 1 ${w - r},${h}`,
        `H ${ax + 7}`,
        `C ${ax + 3.5},${h} ${ax + 1.8},${h + 5.2} ${ax},${h + 6}`,
        `C ${ax - 1.8},${h + 5.2} ${ax - 3.5},${h} ${ax - 7},${h}`,
        `H ${r}`,
        `A ${r},${r} 0 0 1 0,${h - r}`,
        `V ${r}`,
        `A ${r},${r} 0 0 1 ${r},0`,
        'Z',
      ].join(' ');
    } else {
      pathD = [
        `M ${ax + 7},6`,
        `H ${w - r}`,
        `A ${r},${r} 0 0 1 ${w},${6 + r}`,
        `V ${6 + h - r}`,
        `A ${r},${r} 0 0 1 ${w - r},${6 + h}`,
        `H ${r}`,
        `A ${r},${r} 0 0 1 0,${6 + h - r}`,
        `V ${6 + r}`,
        `A ${r},${r} 0 0 1 ${r},6`,
        `H ${ax - 7}`,
        `C ${ax - 3.5},6 ${ax - 1.8},0.8 ${ax},0`,
        `C ${ax + 1.8},0.8 ${ax + 3.5},6 ${ax + 7},6`,
        'Z',
      ].join(' ');
    }

    return createPortal(
      <div
        ref={containerRef}
        className={`action-bubble-container ${placement} ${bubble.tone}`}
        style={{
          top: `${pos?.top ?? -9999}px`,
          left: `${pos?.left ?? -9999}px`,
          visibility: pos ? 'visible' : 'hidden',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="action-bubble-wrapper">
          {/* 单一连续矢量背景：包含圆角框与箭头一体化轮廓与填充 */}
          <svg
            className="action-bubble-svg-shape"
            width={w}
            height={h + 6}
            viewBox={`0 0 ${w} ${h + 6}`}
          >
            <path d={pathD} className="action-bubble-path" />
          </svg>

          {/* 内容文字层：纯净无边框，完美贴合在 SVG 背景上 */}
          <div
            ref={contentRef}
            className="action-bubble-content"
            style={{
              marginTop: placement === 'bottom' ? '6px' : '0px',
            }}
          >
            <span className="action-bubble-icon">
              {bubble.tone === 'success' && <Check size={13} strokeWidth={2.6} />}
              {bubble.tone === 'error' && <AlertCircle size={13} strokeWidth={2.4} />}
              {bubble.tone === 'info' && <Info size={13} strokeWidth={2.4} />}
            </span>
            <span className="action-bubble-text" title={bubble.text}>
              {bubble.text}
            </span>
            {bubble.tone === 'error' && (
              <button
                className="action-bubble-close-btn"
                onClick={closeBubble}
                aria-label={t('common.close', '关闭')}
              >
                <X size={11} />
              </button>
            )}
          </div>
        </div>
      </div>,
      document.body
    );
  };

  return {
    showBubble,
    closeBubble,
    renderBubble,
  };
}
