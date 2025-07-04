import { useState, useEffect } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Heart, Star, Search, Filter, ShoppingBag } from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';
import { useCart } from '@/hooks/use-cart';
import { Link } from 'react-router-dom';
import * as api from '@/lib/api';

const FALLBACK_IMAGES = [
  'https://images.pexels.com/photos/1961792/pexels-photo-1961792.jpeg',
  'https://images.pexels.com/photos/1961795/pexels-photo-1961795.jpeg',
  'https://images.pexels.com/photos/724635/pexels-photo-724635.jpeg',
];

const Products = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const { token } = useAuth();
  const { addToCart } = useCart();
  const [cartMessage, setCartMessage] = useState('');
  const [products, setProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    setLoading(true);
    api.getProducts()
      .then(data => { setProducts(data); setLoading(false); })
      .catch(() => { setError('Failed to load products'); setLoading(false); });
  }, []);

  const categories = [
    { id: 'all', name: 'All Fragrances' },
    { id: 'floral', name: 'Floral' },
    { id: 'oriental', name: 'Oriental' },
    { id: 'fresh', name: 'Fresh' },
    { id: 'woody', name: 'Woody' }
  ];

  const filteredPerfumes = products.filter(perfume => {
    const matchesSearch = perfume.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         perfume.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || perfume.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  const handleAddToCart = async (perfumeId: number) => {
    if (!token) {
      setCartMessage('Please log in to add to cart.');
      return;
    }
    try {
      await addToCart(perfumeId, 1);
      setCartMessage('Added to cart!');
    } catch {
      setCartMessage('Failed to add to cart');
    }
    setTimeout(() => setCartMessage(''), 2000);
  };

  if (loading) return <div className="min-h-screen flex items-center justify-center">Loading products...</div>;
  if (error) return <div className="min-h-screen flex items-center justify-center text-red-500">{error}</div>;

  return (
    <div className="min-h-screen pt-20">
      {/* Header */}
      <section className="py-16 bg-gradient-hero">
        <div className="container mx-auto px-6 text-center">
          <h1 className="text-5xl md:text-6xl font-playfair font-bold mb-6 gradient-text fade-in">
            Our Collection
          </h1>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto fade-in" style={{animationDelay: '0.2s'}}>
            Discover the perfect fragrance that speaks to your soul
          </p>
        </div>
      </section>

      {/* Filters */}
      <section className="py-8 bg-background border-b border-border">
        <div className="container mx-auto px-6">
          <div className="flex flex-col lg:flex-row gap-6 items-center justify-between">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-muted-foreground" />
              <Input
                placeholder="Search fragrances..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>

            {/* Categories */}
            <div className="flex flex-wrap gap-2">
              {categories.map((category) => (
                <Button
                  key={category.id}
                  variant={selectedCategory === category.id ? "default" : "outline"}
                  size="sm"
                  onClick={() => setSelectedCategory(category.id)}
                  className="transition-all duration-300"
                >
                  {category.name}
                </Button>
              ))}
            </div>

            {/* Results Count */}
            <div className="text-sm text-muted-foreground">
              {filteredPerfumes.length} fragrances found
            </div>
          </div>
        </div>
      </section>

      {/* Products Grid */}
      <section className="py-12">
        <div className="container mx-auto px-6">
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-8">
            {filteredPerfumes.map((perfume, index) => (
              <Link to={`/products/${perfume.id}`} key={perfume.id} className="block">
              <Card 
                  className="perfume-card border-border/50 overflow-hidden stagger-animation h-[500px] min-h-[500px] flex flex-col justify-between"
                style={{animationDelay: `${index * 0.1}s`}}
              >
                  <div className="relative overflow-hidden group flex-shrink-0">
                  <img 
                    src={perfume.image} 
                    alt={perfume.name}
                    className="w-full h-80 object-cover transition-transform duration-700 group-hover:scale-110"
                      onError={e => {
                        const img = e.currentTarget;
                        if (!img.dataset.fallback || Number(img.dataset.fallback) >= FALLBACK_IMAGES.length) {
                          img.src = FALLBACK_IMAGES[0];
                          img.dataset.fallback = '1';
                        } else {
                          const nextIdx = Number(img.dataset.fallback);
                          img.src = FALLBACK_IMAGES[nextIdx];
                          img.dataset.fallback = String(nextIdx + 1);
                        }
                      }}
                  />
                  
                  {/* Overlay */}
                  <div className="absolute inset-0 bg-gradient-to-t from-background/90 via-background/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                  
                  {/* Badges */}
                  <div className="absolute top-4 left-4 flex flex-col gap-2">
                    {perfume.isNew && (
                      <Badge className="bg-primary text-primary-foreground">New</Badge>
                    )}
                    {perfume.isBestseller && (
                      <Badge variant="secondary">Bestseller</Badge>
                    )}
                  </div>
                  
                  {/* Heart Icon */}
                  <div className="absolute top-4 right-4">
                    <Button 
                      size="icon" 
                      variant="ghost" 
                      className="h-10 w-10 rounded-full bg-white/20 backdrop-blur-sm hover:bg-white/30 transition-all duration-300"
                    >
                      <Heart className="h-5 w-5 text-white hover:text-primary transition-colors" />
                    </Button>
                  </div>
                </div>
                
                  <CardContent className="p-6 flex flex-col flex-1 min-h-0 justify-between">
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="text-xl font-playfair font-semibold text-foreground hover:text-primary transition-colors">
                      {perfume.name}
                    </h3>
                    <div className="text-right">
                      <div className="text-lg font-bold text-primary">${perfume.price}</div>
                      {perfume.originalPrice && (
                        <div className="text-sm text-muted-foreground line-through">
                          ${perfume.originalPrice}
                        </div>
                      )}
                    </div>
                  </div>
                  
                    <p className="text-muted-foreground mb-4 text-sm leading-relaxed line-clamp-2">
                    {perfume.description}
                  </p>
                  
                  <div className="flex items-center gap-1 mb-4">
                    {[...Array(5)].map((_, i) => (
                      <Star 
                        key={i} 
                        className={`h-4 w-4 ${
                          i < Math.floor(perfume.rating) 
                            ? 'fill-primary text-primary' 
                            : 'text-muted-foreground'
                        }`} 
                      />
                    ))}
                    <span className="text-sm text-muted-foreground ml-2">
                      ({perfume.rating})
                    </span>
                  </div>
                  
                    <div className="flex gap-2 mt-auto">
                      <Button className="flex-1" size="sm" onClick={e => { e.preventDefault(); handleAddToCart(perfume.id); }}>
                      Add to Cart
                    </Button>
                      <Button variant="outline" size="sm" onClick={e => e.preventDefault()}>
                      Details
                    </Button>
                  </div>
                </CardContent>
              </Card>
              </Link>
            ))}
          </div>
          
          {filteredPerfumes.length === 0 && (
            <div className="text-center py-16">
              <div className="text-muted-foreground text-lg mb-4">
                No fragrances found matching your criteria
              </div>
              <Button 
                variant="outline" 
                onClick={() => {
                  setSearchTerm('');
                  setSelectedCategory('all');
                }}
              >
                Clear Filters
              </Button>
            </div>
          )}
        </div>
      </section>

      {cartMessage && (
        <div className="fixed bottom-8 left-1/2 transform -translate-x-1/2 bg-black text-white px-4 py-2 rounded shadow-lg z-50">
          {cartMessage}
        </div>
      )}
    </div>
  );
};

export default Products;