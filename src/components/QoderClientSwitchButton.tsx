import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Play, RotateCw } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useEscCloseTopmost } from '../hooks/useEscClose';
import { getQoderClientVariants, QODER_VARIANT_DISPLAY_NAMES, type QoderVariantId } from '../types/qoder';
import { dropdownLayer, dropdownPlacement, type DropdownPlacement } from '../utils/dropdownPlacement';
import { QoderIcon } from './icons/QoderIcon';
import './QoderClientSwitchButton.css';

export function QoderCurrentClients({ variants }: { variants: readonly QoderVariantId[] }) {
  const { t } = useTranslation();
  if (variants.length === 0) return null;
  return (
    <span className="qoder-current-clients">
      {variants.map((variant) => {
        const label = `${QODER_VARIANT_DISPLAY_NAMES[variant]} · ${t('accounts.status.current', '当前')}`;
        return (
          <span key={variant} className="qoder-current-client" role="img" aria-label={label} title={label}>
            <QoderIcon variant={variant} className="qoder-current-client-icon" />
          </span>
        );
      })}
    </span>
  );
}

interface QoderClientSwitchButtonProps {
  id: string;
  variant: QoderVariantId;
  className: string;
  busy: boolean;
  disabled: boolean;
  onSwitch: (variant: QoderVariantId, anchor: HTMLButtonElement) => void;
}

export function QoderClientSwitchButton({
  id, variant, className, busy, disabled, onSwitch,
}: QoderClientSwitchButtonProps) {
  const { t } = useTranslation();
  const menuId = useId();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [placement, setPlacement] = useState<(DropdownPlacement & { arrowX: number }) | null>(null);
  const expanded = open && !busy && !disabled;
  const visible = expanded && placement !== null;
  const title = t('dashboard.switch', '切换');
  const label = t('qoder.suite.switchTarget', '换号目标');

  const closeMenu = (restoreFocus = false) => {
    if (restoreFocus || menuRef.current?.contains(document.activeElement)) triggerRef.current?.focus();
    setOpen(false);
  };
  useEscCloseTopmost(expanded, () => closeMenu(true), menuRef);

  useLayoutEffect(() => {
    if (!expanded) return;
    const updatePosition = () => {
      const trigger = triggerRef.current;
      if (!trigger) return;
      const rect = trigger.getBoundingClientRect();
      const layers: string[] = [];
      for (let node: HTMLElement | null = trigger; node; node = node.parentElement) {
        layers.push(window.getComputedStyle(node).zIndex);
      }
      const next = dropdownPlacement(
        { left: rect.left + rect.width / 2 - 88, top: rect.top, bottom: rect.bottom, width: rect.width },
        { width: window.innerWidth, height: window.innerHeight },
        'up', 176, 128, dropdownLayer(layers),
      );
      setPlacement({ ...next, arrowX: Math.max(16, Math.min(next.width - 16, rect.left + rect.width / 2 - next.left)) });
    };
    updatePosition();
    window.addEventListener('resize', updatePosition);
    window.addEventListener('scroll', updatePosition, true);
    return () => {
      window.removeEventListener('resize', updatePosition);
      window.removeEventListener('scroll', updatePosition, true);
    };
  }, [expanded]);

  useEffect(() => {
    if (visible) menuRef.current?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus();
  }, [visible]);

  useEffect(() => {
    if (!expanded) return;
    const handlePointerDown = (event: PointerEvent) => {
      if (!(event.target instanceof Node)) return;
      if (triggerRef.current?.contains(event.target) || menuRef.current?.contains(event.target)) return;
      closeMenu();
    };
    document.addEventListener('pointerdown', handlePointerDown);
    return () => document.removeEventListener('pointerdown', handlePointerDown);
  }, [expanded]);

  useEffect(() => {
    if (busy || disabled) setOpen(false);
  }, [busy, disabled]);

  return (
    <>
      <button
        ref={triggerRef}
        id={id}
        type="button"
        className={className}
        title={title}
        aria-label={title}
        aria-haspopup="menu"
        aria-controls={menuId}
        aria-expanded={expanded}
        aria-busy={busy}
        disabled={busy || disabled}
        onClick={() => setOpen((previous) => !previous)}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            setOpen(true);
          }
        }}
      >
        {busy ? <RotateCw size={14} className="loading-spinner" /> : <Play size={14} />}
      </button>
      {/* Keep the content through the exit transition; inert stops interaction as soon as it closes. */}
      {createPortal(
        <div
          ref={menuRef}
          id={menuId}
          role="menu"
          aria-label={label}
          aria-hidden={!visible}
          inert={!visible}
          className={`qoder-client-switch-popover${visible ? ' is-open' : ''}${placement?.bottom !== undefined ? ' above' : ''}`}
          style={{ top: placement?.top, bottom: placement?.bottom, left: placement?.left ?? -9999, width: placement?.width, zIndex: placement?.zIndex }}
          onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget) && event.relatedTarget !== triggerRef.current) closeMenu();
          }}
          onKeyDown={(event) => {
            if (event.key === 'Tab') closeMenu(true);
            const items = Array.from(menuRef.current?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]') ?? []);
            const index = items.indexOf(document.activeElement as HTMLButtonElement);
            const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1
              : event.key === 'ArrowRight' || event.key === 'ArrowDown' ? (index + 1) % items.length
                : event.key === 'ArrowLeft' || event.key === 'ArrowUp' ? (index - 1 + items.length) % items.length : -1;
            if (next >= 0) { event.preventDefault(); items[next]?.focus(); }
          }}
        >
          <span className="qoder-client-switch-arrow" style={{ left: placement?.arrowX }} aria-hidden="true" />
          <div className="qoder-client-switch-content" style={{ maxHeight: placement?.maxHeight }}>
            <div className="qoder-client-switch-label" aria-hidden="true">{label}</div>
            <div className="qoder-client-switch-options">
              {getQoderClientVariants(variant).map((target) => {
                const switchTitle = t('qoder.suite.switchToClient', '切换到 {{client}}', { client: QODER_VARIANT_DISPLAY_NAMES[target] });
                return (
                  <button
                    key={target}
                    type="button"
                    role="menuitem"
                    tabIndex={-1}
                    title={switchTitle}
                    aria-label={switchTitle}
                    className="qoder-client-switch-option"
                    onClick={() => {
                      if (!visible || !triggerRef.current) return;
                      closeMenu(true);
                      onSwitch(target, triggerRef.current);
                    }}
                  >
                    <QoderIcon variant={target} className="qoder-client-switch-icon" />
                    <span>{target.endsWith('_app') ? 'App' : 'IDE'}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>,
        document.body,
      )}
    </>
  );
}
