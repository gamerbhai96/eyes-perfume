import { useCart } from '@/hooks/use-cart';
import { perfumes } from '../data/perfumes';
import { useAuth } from '@/hooks/use-auth';
import { useNavigate, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import confetti from 'canvas-confetti';
import { API_URL } from '@/lib/api';

const Checkout = () => {
  const { cart, fetchCart } = useCart();
  const { token } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    name: '',
    address: '',
    phone: ''
  });
  const [paymentMethod, setPaymentMethod] = useState('paypal');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Address selection state
  const [addresses, setAddresses] = useState(() => {
    const saved = localStorage.getItem('addresses');
    return saved ? JSON.parse(saved) : [];
  });
  const [selectedAddressId, setSelectedAddressId] = useState(addresses[0]?.id || null);
  const [showAddressForm, setShowAddressForm] = useState(addresses.length === 0);

  useEffect(() => {
    const saved = localStorage.getItem('addresses');
    const loaded = saved ? JSON.parse(saved) : [];
    setAddresses(loaded);
    if (loaded.length > 0) setSelectedAddressId(loaded[0].id);
  }, []);

  const total = cart.reduce((sum, item) => {
    const product = perfumes.find(p => p.id === item.perfumeId);
    return product ? sum + product.price * item.quantity : sum;
  }, 0);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleCheckout = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');
    try {
      const res = await fetch(`${API_URL}/checkout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ ...form, paymentMethod })
      });
      const data = await res.json();
      if (!res.ok) setError(data.error || 'Checkout failed');
      else {
        setSuccess('Order placed successfully!');
        fetchCart();
        setTimeout(() => navigate('/orders'), 2000);
      }
    } catch {
      setError('Checkout failed');
    } finally {
      setLoading(false);
    }
  };

  // Add confetti effect on order success
  useEffect(() => {
    if (success) {
      confetti({
        particleCount: 120,
        spread: 80,
        origin: { y: 0.7 },
        zIndex: 9999,
      });
    }
  }, [success]);

  if (!token) return null;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-hero p-6">
      <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1920&h=1080&fit=crop')] bg-cover bg-center opacity-5 pointer-events-none" />
      <div className="w-full max-w-lg relative z-10">
        <Card className="perfume-card border-border/50 fade-in shadow-2xl rounded-2xl animate-fade-in-up" style={{animationDelay: '0.2s'}}>
          <CardHeader className="text-center pb-6">
            <CardTitle className="text-3xl font-playfair font-bold tracking-tight mb-2">Checkout</CardTitle>
            <p className="text-muted-foreground text-base">Complete your order and enjoy your new fragrance!</p>
          </CardHeader>
          <CardContent className="space-y-8">
            {/* Order Summary */}
            <div>
              <h3 className="font-semibold text-lg mb-3 tracking-wide">Order Summary</h3>
              <ul className="space-y-3 mb-3">
                {cart.map(item => {
                  const product = perfumes.find(p => p.id === item.perfumeId);
                  if (!product) return null;
                  return (
                    <li key={item.perfumeId} className="flex items-center gap-4 bg-background/60 rounded-lg p-2">
                      <img src={product.image} alt={product.name} className="w-14 h-14 object-cover rounded-lg border" />
                      <div className="flex-1">
                        <div className="font-semibold text-base">{product.name}</div>
                        <div className="text-xs text-muted-foreground">${product.price} x {item.quantity}</div>
                      </div>
                      <div className="font-bold text-lg">${product.price * item.quantity}</div>
                    </li>
                  );
                })}
              </ul>
              <div className="flex justify-between items-center text-xl font-bold border-t pt-4 mt-2">
                <span>Total:</span>
                <span className="bg-primary/10 text-primary px-4 py-1 rounded-full shadow-inner">${total}</span>
              </div>
            </div>
            <hr className="my-2 border-border/40" />
            {/* Shipping Details */}
            <div>
              <h3 className="font-semibold text-lg mb-3 tracking-wide">Shipping Details</h3>
              {addresses.length > 0 && !showAddressForm ? (
                <div className="mb-4">
                  <div className="font-medium mb-2">Select a saved address:</div>
                  <div className="space-y-2">
                    {addresses.map(addr => (
                      <label key={addr.id} className={`flex items-center gap-3 p-3 rounded border cursor-pointer transition-all ${selectedAddressId === addr.id ? 'border-primary ring-2 ring-primary' : 'border-border'}`}>
                        <input
                          type="radio"
                          name="address"
                          value={addr.id}
                          checked={selectedAddressId === addr.id}
                          onChange={() => setSelectedAddressId(addr.id)}
                          className="accent-primary"
                        />
                        <div className="flex-1">
                          <div className="font-semibold">{addr.name}</div>
                          <div className="text-sm text-muted-foreground">{addr.line1}, {addr.city}, {addr.state} {addr.zip}, {addr.country}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                  <Button variant="outline" className="mt-3" onClick={() => setShowAddressForm(true)}>Add New Address</Button>
                </div>
              ) : (
                <form className="space-y-3 mb-4" onSubmit={e => { e.preventDefault(); setAddresses([...addresses, { ...form, id: Date.now() }]); setShowAddressForm(false); }}>
                  <div>
                    <label className="font-semibold mb-1 block">Label (Home, Work)</label>
                    <input name="name" value={form.name} onChange={handleChange} className="w-full border border-border/60 rounded-xl px-3 py-2 text-base text-black dark:text-white focus:outline-none focus:ring-2 focus:ring-primary transition" required />
                  </div>
                  <div>
                    <label className="font-semibold mb-1 block">Address</label>
                    <input name="address" value={form.address} onChange={handleChange} className="w-full border border-border/60 rounded-xl px-3 py-2 text-base text-black dark:text-white focus:outline-none focus:ring-2 focus:ring-primary transition" required />
                  </div>
                  <div>
                    <label className="font-semibold mb-1 block">Phone</label>
                    <input name="phone" value={form.phone} onChange={handleChange} className="w-full border border-border/60 rounded-xl px-3 py-2 text-base text-black dark:text-white focus:outline-none focus:ring-2 focus:ring-primary transition" required />
                  </div>
                  <Button type="submit" className="w-full">Save Address</Button>
                  {addresses.length > 0 && (
                    <Button type="button" variant="ghost" className="w-full mt-1" onClick={() => setShowAddressForm(false)}>Cancel</Button>
                  )}
                </form>
              )}
              {/* Only show the rest of the form if an address is selected */}
              {((addresses.length > 0 && !showAddressForm) || addresses.length === 0) && (
                <form onSubmit={handleCheckout} className="space-y-5">
                  <hr className="my-2 border-border/40" />
                  <div>
                    <h3 className="font-semibold text-lg mb-3 tracking-wide">Payment Method</h3>
                    <RadioGroup value={paymentMethod} onValueChange={setPaymentMethod} className="grid gap-4 sm:grid-cols-3">
                      <label className={
                        `flex flex-col items-center border rounded-xl p-4 cursor-pointer transition-all duration-200 shadow-sm hover:shadow-md ${paymentMethod === 'paypal' ? 'border-primary ring-2 ring-primary' : 'border-border'}`
                      } htmlFor="paypal">
                        <RadioGroupItem value="paypal" id="paypal" className="mb-2" />
                        <span className="text-3xl mb-1">🅿️</span>
                        <span className="font-medium">PayPal</span>
                        <span className="text-xs text-muted-foreground mt-1">Pay securely with PayPal</span>
                      </label>
                      <label className={
                        `flex flex-col items-center border rounded-xl p-4 cursor-pointer transition-all duration-200 shadow-sm hover:shadow-md ${paymentMethod === 'upi' ? 'border-primary ring-2 ring-primary' : 'border-border'}`
                      } htmlFor="upi">
                        <RadioGroupItem value="upi" id="upi" className="mb-2" />
                        <span className="text-3xl mb-1">🇮🇳</span>
                        <span className="font-medium">UPI</span>
                        <span className="text-xs text-muted-foreground mt-1">Pay via UPI apps</span>
                      </label>
                      <label className={
                        `flex flex-col items-center border rounded-xl p-4 cursor-pointer transition-all duration-200 shadow-sm hover:shadow-md ${paymentMethod === 'cod' ? 'border-primary ring-2 ring-primary' : 'border-border'}`
                      } htmlFor="cod">
                        <RadioGroupItem value="cod" id="cod" className="mb-2" />
                        <span className="text-3xl mb-1">💵</span>
                        <span className="font-medium">Cash on Delivery</span>
                        <span className="text-xs text-muted-foreground mt-1">Pay with cash upon delivery</span>
                      </label>
                    </RadioGroup>
                  </div>
                  {error && <div className="text-red-500 text-sm text-center mt-2">{error}</div>}
                  {success && <div className="text-green-600 text-sm text-center mt-2">{success}</div>}
                  <Button type="submit" className="w-full glow-effect text-lg py-3 rounded-xl mt-2 shadow-lg hover:scale-[1.02] transition-transform" disabled={loading || cart.length === 0}>
                    {loading ? 'Placing Order...' : 'Place Order'}
                  </Button>
                </form>
              )}
            </div>
            <Link to="/cart">
              <Button variant="outline" className="w-full mt-2 rounded-xl">Back to Cart</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Checkout; 