// API utility for admin panel
const API_URL = 'http://localhost:4000/api';

// --- Users ---
export async function getUsers(token: string) {
  const res = await fetch(`${API_URL}/admin/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch users');
  return res.json();
}
export async function updateUser(token: string, id: number, data: any) {
  const res = await fetch(`${API_URL}/admin/users/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update user');
  return res.json();
}
export async function deleteUser(token: string, id: number) {
  const res = await fetch(`${API_URL}/admin/users/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to delete user');
  return res.json();
}

// --- Orders ---
export async function getOrders(token: string) {
  const res = await fetch(`${API_URL}/admin/orders`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to fetch orders');
  return res.json();
}
export async function updateOrder(token: string, id: number, data: any) {
  const res = await fetch(`${API_URL}/admin/orders/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update order');
  return res.json();
}
export async function deleteOrder(token: string, id: number) {
  const res = await fetch(`${API_URL}/admin/orders/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to delete order');
  return res.json();
}

// --- Products ---
export async function getProducts() {
  const res = await fetch(`${API_URL}/products`);
  if (!res.ok) throw new Error('Failed to fetch products');
  return res.json();
}
export async function createProduct(token: string, data: any) {
  const res = await fetch(`${API_URL}/products`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to create product');
  return res.json();
}
export async function updateProduct(token: string, id: number, data: any) {
  const res = await fetch(`${API_URL}/products/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error('Failed to update product');
  return res.json();
}
export async function deleteProduct(token: string, id: number) {
  const res = await fetch(`${API_URL}/products/${id}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error('Failed to delete product');
  return res.json();
} 