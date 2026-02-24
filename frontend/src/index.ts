import type { TangraModule } from './sdk';
import routes from './routes';
import { useWardenFolderStore } from './stores/warden-folder.state';
import { useWardenSecretStore } from './stores/warden-secret.state';
import { useWardenPermissionStore } from './stores/warden-permission.state';
import enUS from './locales/en-US.json';

const wardenModule: TangraModule = {
  id: 'warden',
  version: '1.0.0',
  routes,
  stores: {
    'warden-folder': useWardenFolderStore,
    'warden-secret': useWardenSecretStore,
    'warden-permission': useWardenPermissionStore,
  },
  locales: {
    'en-US': enUS,
  },
};

export default wardenModule;
