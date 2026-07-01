export function isAdminToken(token: string): boolean {
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return Array.isArray(payload.roles) && payload.roles.includes('admin');
  } catch {
    return false;
  }
}
