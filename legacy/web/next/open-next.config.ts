import {defineCloudflareConfig} from '@opennextjs/cloudflare';
// Request-rendered pages need no ISR cache, R2, queues, images or API bindings.
export default defineCloudflareConfig();
