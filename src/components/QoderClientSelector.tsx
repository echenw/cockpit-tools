import { getQoderClientVariants, QODER_VARIANT_DISPLAY_NAMES, type QoderVariantId } from '../types/qoder';
import { QoderIcon } from './icons/QoderIcon';
import './QoderClientSelector.css';

interface QoderClientSelectorProps {
  value: QoderVariantId;
  onChange: (variant: QoderVariantId) => void;
  label: string;
  disabled?: boolean;
}

export function QoderClientSelector({
  value,
  onChange,
  label,
  disabled = false,
}: QoderClientSelectorProps) {
  return (
    <div className="qoder-client-selector" role="group" aria-label={label}>
      {getQoderClientVariants(value).map((variant) => {
        const name = QODER_VARIANT_DISPLAY_NAMES[variant];
        return (
          <button
            key={variant}
            type="button"
            className={`qoder-client-option${value === variant ? ' is-highlighted' : ''}`}
            title={name}
            aria-label={name}
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
