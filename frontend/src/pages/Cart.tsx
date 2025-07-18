import { useAuth } from '@/hooks/use-auth';
import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useCart } from '@/hooks/use-cart';
import { perfumes } from '../data/perfumes';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { API_URL } from '@/lib/api';

interface CartItem {
  perfumeId: number;
  quantity: number;
}

const Cart = () => {
  const { token } = useAuth();
  const navigate = useNavigate();
  const { cart, fetchCart } = useCart();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (!token) navigate('/login');
    else fetchCart();
    // eslint-disable-next-line
  }, [token]);

  const updateItem = async (perfumeId: number, quantity: number) => {
    setLoading(true);
    setError('');
    try {
      await fetch(`${API_URL}/cart`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify({ perfumeId, quantity })
      });
      fetchCart();
    } catch {
      setError('Failed to update cart');
    } finally {
      setLoading(false);
    }
  };

  // Calculate total
  const total = cart.reduce((sum, item) => {
    const product = perfumes.find(p => p.id === item.perfumeId);
    return product ? sum + product.price * item.quantity : sum;
  }, 0);

  if (!token) return null;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-hero p-6">
      <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1920&h=1080&fit=crop')] bg-cover bg-center opacity-5 pointer-events-none" />
      <div className="w-full max-w-md relative z-10">
        <Card className="perfume-card border-border/50 fade-in" style={{animationDelay: '0.2s'}}>
          <CardHeader className="text-center pb-6">
            <CardTitle className="text-2xl font-playfair font-bold">
              Your Cart
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {error && <div className="text-red-500 text-sm text-center mb-2">{error}</div>}
            {success && <div className="text-green-600 text-sm text-center mb-2">{success}</div>}
            {cart.length === 0 ? (
              <div className="text-center text-muted-foreground">Your cart is empty.</div>
            ) : (
              <ul className="space-y-4 mb-4">
                {cart.map(item => {
                  const product = perfumes.find(p => p.id === item.perfumeId);
                  if (!product) return null;
                  return (
                    <li key={item.perfumeId} className="flex items-center gap-4 border-b pb-2">
                      <img src={product.image} alt={product.name} className="w-16 h-16 object-cover rounded" />
                      <div className="flex-1">
                        <div className="font-semibold text-lg">{product.name}</div>
                        <div className="text-sm text-muted-foreground">${product.price} x {item.quantity}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button variant="outline" size="icon" onClick={() => updateItem(item.perfumeId, item.quantity - 1)}>-</Button>
                        <span className="px-2 font-semibold">{item.quantity}</span>
                        <Button variant="outline" size="icon" onClick={() => updateItem(item.perfumeId, item.quantity + 1)}>+</Button>
                        <Button variant="destructive" size="icon" onClick={() => updateItem(item.perfumeId, 0)}>🗑️</Button>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
            {cart.length > 0 && (
              <div className="flex justify-between items-center text-lg font-bold border-t pt-4">
                <span>Total:</span>
                <span>${total}</span>
              </div>
            )}
            <Link to="/">
              <Button variant="outline" className="w-full mt-2">Return to Home</Button>
            </Link>
            <Link to="/checkout">
              <Button className="w-full glow-effect mt-2" disabled={cart.length === 0}>Checkout</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Cart; 