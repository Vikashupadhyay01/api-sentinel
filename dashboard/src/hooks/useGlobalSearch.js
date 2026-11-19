import { useState, useCallback } from 'react';
export function useGlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const toggle = useCallback(() => setOpen(o => !o), []);
  const close = useCallback(() => { setOpen(false); setQuery(''); }, []);
  return { open, query, setQuery, toggle, close };
}
