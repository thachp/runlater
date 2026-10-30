import DocumentContent from './document-content';
import content from './content.json';
export default function NotFound() {
 return <DocumentContent content={content.missing}/>;
}
