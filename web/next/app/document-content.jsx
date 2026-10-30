import parse from 'html-react-parser';
export default function DocumentContent({content}) {
 return <>{parse(content.head, {replace(node) {
  // App Router owns these two document defaults. Avoid duplicate meta tags;
  // all source titles, descriptions, canonical/OG links and theme tags remain.
  if(node.name === 'meta' && (Object.hasOwn(node.attribs, 'charset') || node.attribs.name === 'viewport')) return <></>;
 }})}{parse(content.body)}</>;
}
