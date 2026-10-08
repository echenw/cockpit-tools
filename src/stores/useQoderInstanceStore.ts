import { createInstanceStore } from './createInstanceStore';
import { createQoderInstanceService } from '../services/qoderInstanceService';
import type { QoderInstanceVariantId } from '../types/qoder';

const QODER_INSTANCE_CACHE_KEYS: Record<QoderInstanceVariantId, string> = {
  qoder: 'agtools.qoder.instances.cache',
  qoder_cn_ide: 'agtools.qoder_cn_ide.instances.cache',
};

const createQoderInstanceStoreForVariant = (variantId: QoderInstanceVariantId) =>
  createInstanceStore(
    createQoderInstanceService(variantId),
    QODER_INSTANCE_CACHE_KEYS[variantId],
  );

export const useQoderInstanceStore = createInstanceStore(
  createQoderInstanceService('qoder'),
  QODER_INSTANCE_CACHE_KEYS.qoder,
);

export const useQoderCnIdeInstanceStore = createQoderInstanceStoreForVariant('qoder_cn_ide');

export const QODER_INSTANCE_STORES = {
  qoder: useQoderInstanceStore,
  qoder_cn_ide: useQoderCnIdeInstanceStore,
} satisfies Record<QoderInstanceVariantId, typeof useQoderInstanceStore>;
