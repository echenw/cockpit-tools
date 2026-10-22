import { useTranslation } from 'react-i18next';
import { getQoderClientVariants, QODER_VARIANT_DISPLAY_NAMES, type QoderVariantId } from '../types/qoder';
import { QoderIcon } from './icons/QoderIcon';
import './QoderClientSelector.css';

interface QoderClientSelectorProps {
  value: QoderVariantId;
  onChange: (variant: QoderVariantId) => void;
  label: string;
  currentVariants?: readonly QoderVariantId[];
  disabled?: boolean;
}

export function QoderClientSelector({
  value,
  onChange,
  label,
  currentVariants,
  disabled = false,
}: QoderClientSelectorProps) {
  const { t } = useTranslation();
  return (
    <div className="qoder-client-selector" role="group" aria-label={label}>
      {getQoderClientVariants(value).map((variant) => {
        const name = QODER_VARIANT_DISPLAY_NAMES[variant];
        const isCurrent = currentVariants?.includes(variant) ?? false;
        const isHighlighted = currentVariants === undefined ? value === variant : isCurrent;
        const title = isCurrent ? `${name} · ${t('accounts.status.current', '当前')}` : name;
        return (
          <button
            key={variant}
            type="button"
            className={`qoder-client-option${isHighlighted ? ' is-highlighted' : ''}`}
            title={title}
            aria-label={title}
            aria-pressed={value === variant}
            disabled={disabled}
            onClick={() => onChange(variant)}
          >
            <QoderIcon variant={variant} className="qoder-client-icon" />
          </button>
        );
      })}
    </div>
  );
}
