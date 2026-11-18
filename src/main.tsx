import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import { ErrorBoundary } from './components/ErrorBoundary.tsx';
import { NlaProvider } from './context/NlaContext.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <ErrorBoundary>
    <NlaProvider>
      <App />
    </NlaProvider>
  </ErrorBoundary>
);
