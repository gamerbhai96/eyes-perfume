import { useEffect, useState } from 'react';
import { useAuth } from '@/hooks/use-auth';
import { useNavigate, Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { perfumes } from '../data/perfumes';
import { API_URL } from '@/lib/api';

interface OrderItem {
  perfumeId: number;
  quantity: number;
}

interface Order {
  id: number;
  createdAt: string;
  name: string;
  address: string;
  phone: string;
  items: OrderItem[];
}

const Orders = () => {
  const { token } = useAuth();
  const navigate = useNavigate();
  const [orders, setOrders] = useState<Order[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!token) navigate('/login');
    else fetchOrders();
    // eslint-disable-next-line
  }, [token]);

  const fetchOrders = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API_URL}/orders`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      const data = await res.json();
      setOrders(Array.isArray(data) ? data : []);
    } catch {
      setError('Failed to load orders');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-hero p-6">
      <div className="absolute inset-0 bg-[url('https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=1920&h=1080&fit=crop')] bg-cover bg-center opacity-5" />
      <div className="w-full max-w-2xl relative z-10">
        <Card className="perfume-card border-border/50 fade-in" style={{animationDelay: '0.2s'}}>
          <CardHeader className="text-center pb-6">
            <CardTitle className="text-2xl font-playfair font-bold">
              Order History
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            {loading && <div className="text-center">Loading...</div>}
            {error && <div className="text-red-500 text-sm text-center mb-2">{error}</div>}
            {orders.length === 0 && !loading ? (
              <div className="text-center text-muted-foreground">No orders found.</div>
            ) : (
              <ul className="space-y-8">
                {orders.map((order: Order) => {
                  const orderTotal = order.items.reduce((sum: number, item: OrderItem) => {
                    const product = perfumes.find(p => p.id === item.perfumeId);
                    return product ? sum + product.price * item.quantity : sum;
                  }, 0);
                  return (
                    <li key={order.id} className="border-b pb-4">
                      <div className="mb-2 flex justify-between items-center">
                        <div className="font-semibold">Order #{order.id}</div>
                        <div className="text-sm text-muted-foreground">{new Date(order.createdAt).toLocaleString()}</div>
                      </div>
                      <div className="mb-2 text-sm">
                        <span className="font-semibold">Shipping:</span> {order.name}, {order.address}, {order.phone}
                      </div>
                      <ul className="space-y-2 mb-2">
                        {order.items.map((item: OrderItem) => {
                          const product = perfumes.find(p => p.id === item.perfumeId);
                          if (!product) return null;
                          return (
                            <li key={item.perfumeId} className="flex items-center gap-3">
                              <img src={product.image} alt={product.name} className="w-10 h-10 object-cover rounded" />
                              <div className="flex-1">
                                <div className="font-semibold">{product.name}</div>
                                <div className="text-sm text-muted-foreground">${product.price} x {item.quantity}</div>
                              </div>
                              <div className="font-bold">${product.price * item.quantity}</div>
                            </li>
                          );
                        })}
                      </ul>
                      <div className="flex justify-between items-center text-lg font-bold border-t pt-2">
                        <span>Total:</span>
                        <span>${orderTotal}</span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
            <Link to="/">
              <Button variant="outline" className="w-full mt-2">Return to Home</Button>
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default Orders; 