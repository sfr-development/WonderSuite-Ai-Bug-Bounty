import { Shell } from './components/layout/Shell';
import { UpdateNotification } from './components/UpdateNotification';
import { BrowserDownloadModal } from './components/BrowserDownloadModal';

export default function App() {
  return (
    <>
      <Shell />
      <UpdateNotification />
      <BrowserDownloadModal />
    </>
  );
}
