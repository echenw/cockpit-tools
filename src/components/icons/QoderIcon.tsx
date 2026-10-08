import { CSSProperties } from 'react';
import type { QoderVariantId } from '../../types/qoder';
import qoderAppIcon from '../../assets/icons/qoder-app.png';
import qoderCnAppIcon from '../../assets/icons/qoder-cn-app.png';
import qoderCnIdeIcon from '../../assets/icons/qoder-cn-ide.png';
import qoderIcon from '../../assets/icons/qoder.png';

type QoderIconProps = {
  className?: string;
  style?: CSSProperties;
  variant?: QoderVariantId;
};

const QODER_ICON_BY_VARIANT: Record<QoderVariantId, string> = {
  qoder: qoderIcon,
  qoder_app: qoderAppIcon,
  qoder_cn_ide: qoderCnIdeIcon,
  qoder_cn_app: qoderCnAppIcon,
};

export function QoderIcon({
  className = 'nav-item-icon',
  style,
  variant = 'qoder',
}: QoderIconProps) {
  return (
    <img
      className={className}
      style={style}
      src={QODER_ICON_BY_VARIANT[variant]}
      alt=""
      aria-hidden="true"
      draggable={false}
    />
  );
}
