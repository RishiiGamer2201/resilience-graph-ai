import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
// After index.css, not @import-ed from it: an @import that is not at the top of
// a stylesheet is dropped by the CSS spec, and this one silently was -- the
// whole responsive layer was missing from the bundle while the source looked
// correct. Importing here also fixes the cascade order, which is the point.
import './responsive.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
