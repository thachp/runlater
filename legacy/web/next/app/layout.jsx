import {headers} from 'next/headers';
export const dynamic = 'force-dynamic';
export default async function Layout({children}) {
 // Reading headers opts into request rendering so CSP nonces never enter a shared HTML cache.
 await headers();
 return <html lang="en"><body>{children}</body></html>;
}
