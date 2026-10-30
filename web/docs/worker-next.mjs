import next from './.open-next/worker.js';
import {createWebHandler} from '../next/handler.mjs';
export default createWebHandler('docs', next);
