import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useAuth } from '@/hooks/use-auth';
import { useNavigate } from 'react-router-dom';
import { Badge } from '@/components/ui/badge';
import { AlertDialog, AlertDialogTrigger, AlertDialogContent, AlertDialogHeader, AlertDialogFooter, AlertDialogTitle, AlertDialogDescription, AlertDialogAction, AlertDialogCancel } from '@/components/ui/alert-dialog';
import { Dialog, DialogTrigger, DialogContent, DialogHeader, DialogFooter, DialogTitle, DialogDescription } from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import * as api from '@/lib/api';

const initialProducts = [
  { id: 1, name: 'Rose Essence', price: 60, image: 'https://images.pexels.com/photos/1961792/pexels-photo-1961792.jpeg', description: 'A floral, romantic scent.' },
  { id: 2, name: 'Citrus Dream', price: 30, image: 'https://images.pexels.com/photos/1961795/pexels-photo-1961795.jpeg', description: 'A fresh, citrusy fragrance.' },
  { id: 3, name: 'Ocean Breeze', price: 80, image: 'https://images.pexels.com/photos/724635/pexels-photo-724635.jpeg', description: 'A cool, aquatic aroma.' },
];

const Admin = () => {
  const { user, token, loading } = useAuth();
  // DEBUG: Log user info
  console.log('Admin page user:', user);
  const [tab, setTab] = useState('products');
  const [products, setProducts] = useState([]);
  const [loadingProducts, setLoadingProducts] = useState(false);
  const [productError, setProductError] = useState('');
  const [editingProduct, setEditingProduct] = useState(null);
  const [productForm, setProductForm] = useState({ name: '', price: '', image: '', description: '' });
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [authError, setAuthError] = useState('');
  const navigate = useNavigate();
  const { toast } = useToast();
  // Users tab state
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [userError, setUserError] = useState('');
  const [editingUserId, setEditingUserId] = useState(null);
  const [userForm, setUserForm] = useState({ firstName: '', lastName: '', email: '', role: 'user' });
  const [showUserDialog, setShowUserDialog] = useState(false);
  const [userToEdit, setUserToEdit] = useState(null);
  const [userToDelete, setUserToDelete] = useState(null);
  // Orders tab state
  const [orders, setOrders] = useState([]);
  const [loadingOrders, setLoadingOrders] = useState(false);
  const [orderError, setOrderError] = useState('');
  const [editingOrderId, setEditingOrderId] = useState(null);
  const [orderForm, setOrderForm] = useState({ name: '', address: '', phone: '' });
  const [showOrderDialog, setShowOrderDialog] = useState(false);
  const [orderToEdit, setOrderToEdit] = useState(null);
  const [orderToDelete, setOrderToDelete] = useState(null);

  useEffect(() => {
    if (loading) return; // Wait for context to hydrate
    // Only check when on /admin
    if (window.location.pathname === '/admin') {
      if (!user) {
        setAuthError('You must be logged in as an admin to access this page.');
        setCheckingAuth(false);
        setTimeout(() => navigate('/login', { state: { from: { pathname: '/admin' } } }), 1500);
        return;
      }
      if (user.role !== 'admin') {
        setAuthError('You are not authorized to access the admin panel.');
        setCheckingAuth(false);
        setTimeout(() => navigate('/'), 1500);
        return;
      }
    }
    setCheckingAuth(false);
  }, [user, navigate, loading]);

  useEffect(() => {
    if (!token || checkingAuth) return;
    setLoadingProducts(true);
    api.getProducts()
      .then(data => { setProducts(data); setLoadingProducts(false); })
      .catch(() => { setProductError('Failed to load products'); setLoadingProducts(false); });
  }, [token, checkingAuth]);

  // Fetch users when Users tab is selected
  useEffect(() => {
    if (tab !== 'users' || !token) return;
    setLoadingUsers(true);
    setUserError('');
    api.getUsers(token)
      .then(data => { setUsers(data); setLoadingUsers(false); })
      .catch(() => { setUserError('Failed to load users'); setLoadingUsers(false); });
  }, [tab, token]);

  // Fetch orders when Orders tab is selected
  useEffect(() => {
    if (tab !== 'orders' || !token) return;
    setLoadingOrders(true);
    setOrderError('');
    api.getOrders(token)
      .then(data => { setOrders(data); setLoadingOrders(false); })
      .catch(() => { setOrderError('Failed to load orders'); setLoadingOrders(false); });
  }, [tab, token]);

  if (loading || checkingAuth) {
    return <div className="min-h-screen flex items-center justify-center">Checking admin access...</div>;
  }
  if (authError) {
    return <div className="min-h-screen flex items-center justify-center text-red-500 text-xl">{authError}</div>;
  }

  const handleProductChange = e => setProductForm({ ...productForm, [e.target.name]: e.target.value });

  const handleAddProduct = async () => {
    setLoadingProducts(true);
    setProductError('');
    try {
      const newProduct = await api.createProduct(token, { ...productForm, price: Number(productForm.price) });
      setProducts([...products, newProduct]);
      setProductForm({ name: '', price: '', image: '', description: '' });
      toast({ title: 'Product added', description: 'Product created successfully.' });
    } catch {
      setProductError('Failed to add product');
      toast({ title: 'Error', description: 'Failed to add product.', variant: 'destructive' });
    }
    setLoadingProducts(false);
  };
  const handleEditProduct = p => {
    setEditingProduct(p.id);
    setProductForm({ name: p.name, price: p.price, image: p.image, description: p.description });
  };
  const handleUpdateProduct = async () => {
    setLoadingProducts(true);
    setProductError('');
    try {
      await api.updateProduct(token, editingProduct, { ...productForm, price: Number(productForm.price) });
      setProducts(products.map(p => p.id === editingProduct ? { ...productForm, id: editingProduct, price: Number(productForm.price) } : p));
      setEditingProduct(null);
      setProductForm({ name: '', price: '', image: '', description: '' });
      toast({ title: 'Product updated', description: 'Product updated successfully.' });
    } catch {
      setProductError('Failed to update product');
      toast({ title: 'Error', description: 'Failed to update product.', variant: 'destructive' });
    }
    setLoadingProducts(false);
  };
  const handleDeleteProduct = async id => {
    setLoadingProducts(true);
    setProductError('');
    try {
      await api.deleteProduct(token, id);
      setProducts(products.filter(p => p.id !== id));
      toast({ title: 'Product deleted', description: 'Product deleted successfully.' });
    } catch {
      setProductError('Failed to delete product');
      toast({ title: 'Error', description: 'Failed to delete product.', variant: 'destructive' });
    }
    setLoadingProducts(false);
  };

  const handleEditUser = (user) => {
    setEditingUserId(user.id);
    setUserForm({ firstName: user.firstName, lastName: user.lastName, email: user.email, role: user.role });
  };
  const handleUserFormChange = e => setUserForm({ ...userForm, [e.target.name]: e.target.value });
  const openUserEdit = (user) => {
    setUserToEdit(user);
    setUserForm({ firstName: user.firstName, lastName: user.lastName, email: user.email, role: user.role });
    setShowUserDialog(true);
  };
  const closeUserEdit = () => {
    setShowUserDialog(false);
    setUserToEdit(null);
    setUserForm({ firstName: '', lastName: '', email: '', role: 'user' });
    setEditingUserId(null);
  };
  const handleUpdateUser = async (id) => {
    setLoadingUsers(true);
    setUserError('');
    try {
      await api.updateUser(token, id, userForm);
      setUsers(users.map(u => u.id === id ? { ...u, ...userForm } : u));
      toast({ title: 'User updated', description: 'User details updated successfully.' });
      closeUserEdit();
    } catch {
      setUserError('Failed to update user');
      toast({ title: 'Error', description: 'Failed to update user.', variant: 'destructive' });
    }
    setLoadingUsers(false);
  };
  const openUserDelete = (user) => setUserToDelete(user);
  const closeUserDelete = () => setUserToDelete(null);
  const handleDeleteUser = async (id) => {
    setLoadingUsers(true);
    setUserError('');
    try {
      await api.deleteUser(token, id);
      setUsers(users.filter(u => u.id !== id));
      toast({ title: 'User deleted', description: 'User deleted successfully.' });
      closeUserDelete();
    } catch {
      setUserError('Failed to delete user');
      toast({ title: 'Error', description: 'Failed to delete user.', variant: 'destructive' });
    }
    setLoadingUsers(false);
  };

  const handleEditOrder = (order) => {
    setEditingOrderId(order.id);
    setOrderForm({ name: order.name, address: order.address, phone: order.phone });
  };
  const handleOrderFormChange = e => setOrderForm({ ...orderForm, [e.target.name]: e.target.value });
  const openOrderEdit = (order) => {
    setOrderToEdit(order);
    setOrderForm({ name: order.name, address: order.address, phone: order.phone });
    setShowOrderDialog(true);
  };
  const closeOrderEdit = () => {
    setShowOrderDialog(false);
    setOrderToEdit(null);
    setOrderForm({ name: '', address: '', phone: '' });
    setEditingOrderId(null);
  };
  const handleUpdateOrder = async (id) => {
    setLoadingOrders(true);
    setOrderError('');
    try {
      await api.updateOrder(token, id, orderForm);
      setOrders(orders.map(o => o.id === id ? { ...o, ...orderForm } : o));
      toast({ title: 'Order updated', description: 'Order details updated successfully.' });
      closeOrderEdit();
    } catch {
      setOrderError('Failed to update order');
      toast({ title: 'Error', description: 'Failed to update order.', variant: 'destructive' });
    }
    setLoadingOrders(false);
  };
  const openOrderDelete = (order) => setOrderToDelete(order);
  const closeOrderDelete = () => setOrderToDelete(null);
  const handleDeleteOrder = async (id) => {
    setLoadingOrders(true);
    setOrderError('');
    try {
      await api.deleteOrder(token, id);
      setOrders(orders.filter(o => o.id !== id));
      toast({ title: 'Order deleted', description: 'Order deleted successfully.' });
      closeOrderDelete();
    } catch {
      setOrderError('Failed to delete order');
      toast({ title: 'Error', description: 'Failed to delete order.', variant: 'destructive' });
    }
    setLoadingOrders(false);
  };

  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-gradient-hero">
      {/* Sidebar */}
      <div className="w-full md:w-64 bg-background/80 border-r border-border p-6 flex flex-col gap-4">
        <div className="text-2xl font-bold mb-8">Admin Panel</div>
        <Button variant={tab === 'products' ? 'default' : 'outline'} onClick={() => setTab('products')} className="w-full">Products</Button>
        <Button variant={tab === 'orders' ? 'default' : 'outline'} onClick={() => setTab('orders')} className="w-full">Orders</Button>
        <Button variant={tab === 'users' ? 'default' : 'outline'} onClick={() => setTab('users')} className="w-full">Users</Button>
      </div>
      {/* Main Content */}
      <div className="flex-1 p-8">
        {tab === 'products' && (
          <div>
            <h2 className="text-xl font-bold mb-4">Manage Products</h2>
            {productError && <div className="text-red-500 mb-2">{productError}</div>}
            <div className="mb-6">
              <form className="grid grid-cols-1 md:grid-cols-2 gap-4 items-end" onSubmit={e => { e.preventDefault(); editingProduct ? handleUpdateProduct() : handleAddProduct(); }}>
                <Input name="name" placeholder="Name" value={productForm.name} onChange={handleProductChange} required />
                <Input name="price" placeholder="Price" type="number" value={productForm.price} onChange={handleProductChange} required />
                <Input name="image" placeholder="Image URL" value={productForm.image} onChange={handleProductChange} required />
                <Input name="description" placeholder="Description" value={productForm.description} onChange={handleProductChange} required />
                <Button type="submit" className="col-span-1 md:col-span-2" disabled={loadingProducts}>{editingProduct ? 'Update Product' : 'Add Product'}</Button>
                {editingProduct && <Button type="button" variant="ghost" className="col-span-1 md:col-span-2" onClick={() => { setEditingProduct(null); setProductForm({ name: '', price: '', image: '', description: '' }); }}>Cancel</Button>}
              </form>
            </div>
            {loadingProducts ? (
              <div>Loading...</div>
            ) : (
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                {products.map(p => (
                  <Card key={p.id} className="flex flex-col">
                    <img src={p.image} alt={p.name} className="w-full h-40 object-cover rounded-t" />
                    <CardContent className="flex-1 flex flex-col justify-between">
                      <div>
                        <div className="font-bold text-lg">{p.name}</div>
                        <div className="text-primary font-semibold mb-2">${p.price}</div>
                        <div className="text-muted-foreground text-sm mb-2">{p.description}</div>
                      </div>
                      <div className="flex gap-2 mt-2">
                        <Button size="sm" variant="outline" onClick={() => handleEditProduct(p)}>Edit</Button>
                        <Button size="sm" variant="destructive" onClick={() => handleDeleteProduct(p.id)} disabled={loadingProducts}>Delete</Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}
        {tab === 'orders' && (
          <div>
            <h2 className="text-xl font-bold mb-4">Manage Orders</h2>
            {orderError && <div className="text-red-500 mb-2">{orderError}</div>}
            {loadingOrders ? (
              <div>Loading orders...</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full border text-sm">
                  <thead>
                    <tr className="bg-muted">
                      <th className="p-2 border">ID</th>
                      <th className="p-2 border">User</th>
                      <th className="p-2 border">Created At</th>
                      <th className="p-2 border">Name</th>
                      <th className="p-2 border">Address</th>
                      <th className="p-2 border">Phone</th>
                      <th className="p-2 border">Items</th>
                      <th className="p-2 border">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {orders.map(o => (
                      <tr key={o.id}>
                        <td className="p-2 border">{o.id}</td>
                        <td className="p-2 border">{o.firstName} {o.lastName} <br /><span className="text-xs text-muted-foreground">{o.email}</span></td>
                        <td className="p-2 border">{new Date(o.createdAt).toLocaleString()}</td>
                        <td className="p-2 border">{o.name}</td>
                        <td className="p-2 border">{o.address}</td>
                        <td className="p-2 border">{o.phone}</td>
                        <td className="p-2 border">
                          <ul className="list-disc pl-4">
                            {o.items && o.items.length > 0 ? o.items.map(item => (
                              <li key={item.perfumeId}>Perfume #{item.perfumeId} x {item.quantity}</li>
                            )) : <li className="text-muted-foreground">No items</li>}
                          </ul>
                        </td>
                        <td className="p-2 border">
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button size="sm" variant="outline" onClick={() => openOrderEdit(o)}>Edit</Button>
                            </DialogTrigger>
                          </Dialog>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button size="sm" variant="destructive" onClick={() => openOrderDelete(o)}>Delete</Button>
                            </AlertDialogTrigger>
                          </AlertDialog>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Dialog open={showOrderDialog} onOpenChange={setShowOrderDialog}>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Edit Order</DialogTitle>
                      <DialogDescription>Update order details.</DialogDescription>
                    </DialogHeader>
                    <form onSubmit={e => { e.preventDefault(); handleUpdateOrder(orderToEdit.id); }} className="space-y-4">
                      <Input name="name" value={orderForm.name} onChange={handleOrderFormChange} placeholder="Name" required />
                      <Input name="address" value={orderForm.address} onChange={handleOrderFormChange} placeholder="Address" required />
                      <Input name="phone" value={orderForm.phone} onChange={handleOrderFormChange} placeholder="Phone" required />
                      <DialogFooter>
                        <Button type="submit">Save</Button>
                        <Button type="button" variant="ghost" onClick={closeOrderEdit}>Cancel</Button>
                      </DialogFooter>
                    </form>
                  </DialogContent>
                </Dialog>
                <AlertDialog open={!!orderToDelete} onOpenChange={open => { if (!open) closeOrderDelete(); }}>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete Order</AlertDialogTitle>
                      <AlertDialogDescription>Are you sure you want to delete this order? This action cannot be undone.</AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel onClick={closeOrderDelete}>Cancel</AlertDialogCancel>
                      <AlertDialogAction onClick={() => handleDeleteOrder(orderToDelete.id)}>Delete</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            )}
          </div>
        )}
        {tab === 'users' && (
          <div>
            <h2 className="text-xl font-bold mb-4">Manage Users</h2>
            {userError && <div className="text-red-500 mb-2">{userError}</div>}
            {loadingUsers ? (
              <div>Loading users...</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="min-w-full border text-sm">
                  <thead>
                    <tr className="bg-muted">
                      <th className="p-2 border">ID</th>
                      <th className="p-2 border">First Name</th>
                      <th className="p-2 border">Last Name</th>
                      <th className="p-2 border">Email</th>
                      <th className="p-2 border">Role</th>
                      <th className="p-2 border">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(u => (
                      <tr key={u.id}>
                        <td className="p-2 border">{u.id}</td>
                        <td className="p-2 border">{u.firstName}</td>
                        <td className="p-2 border">{u.lastName}</td>
                        <td className="p-2 border">{u.email}</td>
                        <td className="p-2 border"><Badge variant={u.role === 'admin' ? 'secondary' : 'default'}>{u.role}</Badge></td>
                        <td className="p-2 border">
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button size="sm" variant="outline" onClick={() => openUserEdit(u)}>Edit</Button>
                            </DialogTrigger>
                          </Dialog>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button size="sm" variant="destructive" onClick={() => openUserDelete(u)}>Delete</Button>
                            </AlertDialogTrigger>
                          </AlertDialog>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <Dialog open={showUserDialog} onOpenChange={setShowUserDialog}>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Edit User</DialogTitle>
                      <DialogDescription>Update user details and role.</DialogDescription>
                    </DialogHeader>
                    <form onSubmit={e => { e.preventDefault(); handleUpdateUser(userToEdit.id); }} className="space-y-4">
                      <Input name="firstName" value={userForm.firstName} onChange={handleUserFormChange} placeholder="First Name" required />
                      <Input name="lastName" value={userForm.lastName} onChange={handleUserFormChange} placeholder="Last Name" required />
                      <Input name="email" value={userForm.email} onChange={handleUserFormChange} placeholder="Email" required />
                      <select name="role" value={userForm.role} onChange={handleUserFormChange} className="border rounded px-2 py-1 w-full">
                        <option value="user">user</option>
                        <option value="admin">admin</option>
                      </select>
                      <DialogFooter>
                        <Button type="submit">Save</Button>
                        <Button type="button" variant="ghost" onClick={closeUserEdit}>Cancel</Button>
                      </DialogFooter>
                    </form>
                  </DialogContent>
                </Dialog>
                <AlertDialog open={!!userToDelete} onOpenChange={open => { if (!open) closeUserDelete(); }}>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Delete User</AlertDialogTitle>
                      <AlertDialogDescription>Are you sure you want to delete this user? This action cannot be undone.</AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel onClick={closeUserDelete}>Cancel</AlertDialogCancel>
                      <AlertDialogAction onClick={() => handleDeleteUser(userToDelete.id)}>Delete</AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default Admin; 