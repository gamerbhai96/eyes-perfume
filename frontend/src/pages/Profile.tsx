import { useAuth } from '@/hooks/use-auth';
import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Sparkles, User, Mail, Lock, Home, Trash2, Edit, ShoppingBag, Repeat } from 'lucide-react';
import { API_URL } from '@/lib/api';

const Profile = () => {
  const { user, logout, token } = useAuth();
  const navigate = useNavigate();
  const [profile, setProfile] = useState(user);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');
  const [form, setForm] = useState({
    firstName: user?.firstName || '',
    lastName: user?.lastName || '',
    email: user?.email || '',
    password: ''
  });
  const [addresses, setAddresses] = useState(() => {
    const saved = localStorage.getItem('addresses');
    return saved ? JSON.parse(saved) : [];
  });
  const [editingAddress, setEditingAddress] = useState(null);
  const [addressForm, setAddressForm] = useState({ name: '', line1: '', city: '', state: '', zip: '', country: '' });
  const mockOrders = [
    { id: 101, date: '2024-06-01', total: 120, items: [
      { id: 1, name: 'Rose Essence', qty: 1, price: 60 },
      { id: 2, name: 'Citrus Dream', qty: 2, price: 30 },
    ]},
    { id: 102, date: '2024-05-15', total: 80, items: [
      { id: 3, name: 'Ocean Breeze', qty: 1, price: 80 },
    ]},
  ];
  const [orders, setOrders] = useState(mockOrders);

  useEffect(() => {
    if (!token) navigate('/login');
    else {
      fetch(`${API_URL}/profile`, {
        headers: { Authorization: `Bearer ${token}` }
      })
        .then(res => res.json())
        .then(data => setProfile(data));
    }
  }, [token, navigate]);

  useEffect(() => {
    localStorage.setItem('addresses', JSON.stringify(addresses));
  }, [addresses]);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await fetch(`${API_URL}/profile`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(form)
      });
      const data = await res.json();
      if (!res.ok) setError(data.error || 'Update failed');
      else setSuccess('Profile updated!');
    } catch {
      setError('Network error');
    } finally {
      setLoading(false);
    }
  };

  const handleAddressChange = e => setAddressForm({ ...addressForm, [e.target.name]: e.target.value });
  const handleAddAddress = () => {
    setAddresses([...addresses, { ...addressForm, id: Date.now() }]);
    setAddressForm({ name: '', line1: '', city: '', state: '', zip: '', country: '' });
    setEditingAddress(null);
  };
  const handleEditAddress = addr => {
    setEditingAddress(addr.id);
    setAddressForm(addr);
  };
  const handleUpdateAddress = () => {
    setAddresses(addresses.map(a => a.id === editingAddress ? { ...addressForm, id: editingAddress } : a));
    setAddressForm({ name: '', line1: '', city: '', state: '', zip: '', country: '' });
    setEditingAddress(null);
  };
  const handleDeleteAddress = id => setAddresses(addresses.filter(a => a.id !== id));
  const handleReorder = order => {
    // Here you would call your addToCart logic for each item
    alert('Reordered items from order #' + order.id);
  };

  if (!profile) return null;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-hero p-6 relative overflow-hidden">
      {/* Unsplash background overlay */}
      <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1920&h=1080&fit=crop')] bg-cover bg-center opacity-5 pointer-events-none" />
      <div className="w-full max-w-md relative z-10">
        {/* Logo */}
        <div className="text-center mb-8 fade-in">
          <Link to="/" className="inline-flex items-center gap-3 group">
            <div className="relative">
              <Sparkles className="h-10 w-10 text-primary group-hover:rotate-12 transition-transform duration-300" />
              <div className="absolute inset-0 h-10 w-10 text-primary opacity-30 group-hover:animate-ping" />
            </div>
            <span className="text-3xl font-playfair font-bold gradient-text">
              EYES
            </span>
          </Link>
        </div>
        <Card className="perfume-card border-border/50 fade-in" style={{animationDelay: '0.2s'}}>
          <CardHeader className="text-center pb-6">
            <CardTitle className="text-2xl font-playfair font-bold">
              My Profile
            </CardTitle>
            <CardDescription className="text-muted-foreground">
              Update your details and keep your account fresh
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <form onSubmit={handleUpdate} className="space-y-4">
              {/* First Name */}
              <div className="space-y-2">
                <Label htmlFor="firstName" className="text-sm font-medium">
                  First Name
                </Label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    id="firstName"
                    name="firstName"
                    type="text"
                    placeholder="First Name"
                    value={form.firstName}
                    onChange={handleChange}
                    className="pl-10"
                    required
                  />
                </div>
              </div>
              {/* Last Name */}
              <div className="space-y-2">
                <Label htmlFor="lastName" className="text-sm font-medium">
                  Last Name
                </Label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    id="lastName"
                    name="lastName"
                    type="text"
                    placeholder="Last Name"
                    value={form.lastName}
                    onChange={handleChange}
                    className="pl-10"
                    required
                  />
                </div>
              </div>
              {/* Email */}
              <div className="space-y-2">
                <Label htmlFor="email" className="text-sm font-medium">
                  Email Address
                </Label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    placeholder="your@email.com"
                    value={form.email}
                    onChange={handleChange}
                    className="pl-10"
                    required
                  />
                </div>
              </div>
              {/* Password */}
              <div className="space-y-2">
                <Label htmlFor="password" className="text-sm font-medium">
                  Password
                </Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
                  <Input
                    id="password"
                    name="password"
                    type="password"
                    placeholder="Leave blank to keep current password"
                    value={form.password}
                    onChange={handleChange}
                    className="pl-10"
                  />
                </div>
              </div>
              {/* Error/Success */}
              {error && <div className="text-red-500 text-sm text-center">{error}</div>}
              {success && <div className="text-green-600 text-sm text-center">{success}</div>}
              {/* Submit Button */}
              <Button type="submit" className="w-full glow-effect" disabled={loading}>
                {loading ? 'Updating...' : 'Update Profile'}
              </Button>
            </form>
            <Button
              variant="destructive"
              className="w-full mt-2"
              onClick={() => { logout(); navigate('/login'); }}
            >
              Logout
            </Button>
            {/* Addresses Section */}
            <div className="mt-10">
              <h2 className="text-lg mb-2 flex items-center gap-2 font-bold"><Home className="h-5 w-5" /> Addresses</h2>
              <div className="space-y-2">
                {addresses.map(addr => (
                  <div key={addr.id} className="flex items-center gap-4 bg-secondary/30 rounded p-3">
                    <div className="flex-1">
                      <div className="font-semibold">{addr.name}</div>
                      <div className="text-sm text-muted-foreground">{addr.line1}, {addr.city}, {addr.state} {addr.zip}, {addr.country}</div>
                    </div>
                    <Button size="icon" variant="ghost" onClick={() => handleEditAddress(addr)}><Edit className="h-4 w-4" /></Button>
                    <Button size="icon" variant="destructive" onClick={() => handleDeleteAddress(addr.id)}><Trash2 className="h-4 w-4" /></Button>
                  </div>
                ))}
              </div>
              {/* Add/Edit Address Form */}
              <form className="grid grid-cols-2 gap-2 mt-4" onSubmit={e => { e.preventDefault(); editingAddress ? handleUpdateAddress() : handleAddAddress(); }}>
                <Input name="name" placeholder="Label (Home, Work)" value={addressForm.name} onChange={handleAddressChange} required />
                <Input name="line1" placeholder="Address Line" value={addressForm.line1} onChange={handleAddressChange} required />
                <Input name="city" placeholder="City" value={addressForm.city} onChange={handleAddressChange} required />
                <Input name="state" placeholder="State" value={addressForm.state} onChange={handleAddressChange} required />
                <Input name="zip" placeholder="ZIP" value={addressForm.zip} onChange={handleAddressChange} required />
                <Input name="country" placeholder="Country" value={addressForm.country} onChange={handleAddressChange} required />
                <Button type="submit" className="col-span-2 mt-2 w-full">{editingAddress ? 'Update Address' : 'Add Address'}</Button>
              </form>
            </div>
            {/* Order History Section */}
            <div className="mt-10">
              <h2 className="text-lg mb-2 flex items-center gap-2 font-bold"><ShoppingBag className="h-5 w-5" /> Order History</h2>
              <div className="space-y-4">
                {orders.map(order => (
                  <div key={order.id} className="bg-secondary/30 rounded p-3">
                    <div className="flex justify-between items-center mb-2">
                      <div className="font-semibold">Order #{order.id}</div>
                      <div className="text-sm text-muted-foreground">{order.date}</div>
                      <div className="text-primary font-bold">${order.total}</div>
                      <Button size="sm" variant="outline" onClick={() => handleReorder(order)}><Repeat className="h-4 w-4 mr-1" /> Reorder</Button>
                    </div>
                    <div className="text-sm text-muted-foreground">
                      {order.items.map(item => (
                        <div key={item.id} className="flex gap-2 items-center">
                          <span className="font-medium">{item.name}</span>
                          <span>x{item.qty}</span>
                          <span>${item.price}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Profile; 