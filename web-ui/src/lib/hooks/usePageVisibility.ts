'use client';

import { useState, useEffect, useCallback } from 'react';

/**
 * Hook that tracks whether the browser tab/window is active.
 * Returns false when:
 * - The tab is hidden (user switched browser tabs)
 * - The browser window lost focus (user switched to another application)
 */
export function usePageVisibility(): boolean {
  const [isVisible, setIsVisible] = useState(true);

  const update = useCallback(() => {
    const visible = !document.hidden && document.hasFocus();
    console.log('[usePageVisibility]', visible ? 'ACTIVE' : 'INACTIVE', '| hidden:', document.hidden, 'hasFocus:', document.hasFocus());
    setIsVisible(visible);
  }, []);

  useEffect(() => {
    document.addEventListener('visibilitychange', update);
    window.addEventListener('focus', update);
    window.addEventListener('blur', update);
    return () => {
      document.removeEventListener('visibilitychange', update);
      window.removeEventListener('focus', update);
      window.removeEventListener('blur', update);
    };
  }, [update]);

  return isVisible;
}
