import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Link } from 'react-router-dom';
import { Sparkles, Star, Heart, Gift } from 'lucide-react';
import { useAuth } from '@/hooks/use-auth';
import { useCart } from '@/hooks/use-cart';
import { useState } from 'react';

const FALLBACK_IMAGES = [
  'https://images.pexels.com/photos/1961792/pexels-photo-1961792.jpeg',
  'https://images.pexels.com/photos/1961795/pexels-photo-1961795.jpeg',
  'https://images.pexels.com/photos/724635/pexels-photo-724635.jpeg',
];

const Landing = () => {
  const { token } = useAuth();
  const { addToCart } = useCart();
  const [cartMessage, setCartMessage] = useState('');

  const featuredPerfumes = [
    {
      id: 1,
      name: "Mystic Rose",
      price: "$89",
      image: "https://images.unsplash.com/photo-1541643600914-78b084683601?w=400&h=500&fit=crop",
      description: "Enchanting floral essence"
    },
    {
      id: 2,
      name: "Golden Amber",
      price: "$95",
      image: "https://images.unsplash.com/photo-1588405748880-12d1d2a59d32?w=400&h=500&fit=crop",
      description: "Warm and luxurious"
    },
    {
      id: 3,
      name: "Ocean Breeze",
      price: "$78",
      image: "https://images.unsplash.com/photo-1595425970377-c9703cf48b6b?w=400&h=500&fit=crop",
      description: "Fresh aquatic notes"
    },
    {
      id: 4,
      name: "Citrus Dream",
      price: "$80",
      image: "https://images.pexels.com/photos/1961795/pexels-photo-1961795.jpeg",
      description: "A vibrant citrus blend with a touch of sweetness."
    }
  ];

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

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center justify-center bg-gradient-hero overflow-hidden">
        <div className="absolute inset-0 bg-[url('https://images.pexels.com/photos/965989/pexels-photo-965989.jpeg')] bg-cover bg-center opacity-10" />
        
        <div className="container mx-auto px-6 text-center relative z-10">
          <div className="max-w-4xl mx-auto">
            <div className="float-animation">
              <Sparkles className="h-16 w-16 text-primary mx-auto mb-8" />
            </div>
            
            <h1 className="text-6xl md:text-8xl font-playfair font-bold mb-6 fade-in">
              <span className="gradient-text">EYES</span>
            </h1>
            
            <p className="text-xl md:text-2xl text-muted-foreground mb-8 fade-in" style={{animationDelay: '0.2s'}}>
              Where every fragrance tells a story
            </p>
            
            <p className="text-lg text-foreground/80 mb-12 max-w-2xl mx-auto fade-in" style={{animationDelay: '0.4s'}}>
              Discover our collection of luxury perfumes crafted with the finest ingredients. 
              Each scent is a journey through emotions, memories, and dreams.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-6 justify-center fade-in" style={{animationDelay: '0.6s'}}>
              <Link to="/products">
                <Button size="lg" className="glow-effect text-lg px-8 py-4">
                  Explore Collection
                </Button>
              </Link>
              <Button variant="outline" size="lg" className="text-lg px-8 py-4">
                Discover More
              </Button>
            </div>
          </div>
        </div>
        
        {/* Floating Elements */}
        <div className="absolute top-20 left-10 float-animation" style={{animationDelay: '1s'}}>
          <div className="w-3 h-3 bg-primary rounded-full opacity-60" />
        </div>
        <div className="absolute top-40 right-20 float-animation" style={{animationDelay: '2s'}}>
          <div className="w-2 h-2 bg-primary-glow rounded-full opacity-40" />
        </div>
        <div className="absolute bottom-40 left-20 float-animation" style={{animationDelay: '1.5s'}}>
          <div className="w-4 h-4 bg-primary rounded-full opacity-50" />
        </div>
      </section>

      {/* Featured Products */}
      <section className="py-24 bg-background">
        <div className="container mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl md:text-5xl font-playfair font-bold mb-6 gradient-text">
              Featured Collection
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Handpicked fragrances that capture the essence of elegance and sophistication
            </p>
          </div>
          
          <div className="grid md:grid-cols-4 gap-8 max-w-6xl mx-auto">
            {featuredPerfumes.map((perfume, index) => (
              <Card 
                key={perfume.id} 
                className="perfume-card border-border/50 stagger-animation overflow-hidden cursor-pointer"
                style={{ animationDelay: `${index * 0.2}s` }}
              >
                <Link
                  to={`/products/${perfume.id}`}
                  className="block group"
                  style={{ textDecoration: 'none' }}
                  tabIndex={-1}
              >
                <div className="relative overflow-hidden">
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
                  <div className="absolute inset-0 bg-gradient-to-t from-background/80 via-transparent to-transparent" />
                  <div className="absolute top-4 right-4">
                    <Heart className="h-6 w-6 text-white/80 hover:text-primary transition-colors cursor-pointer" />
                  </div>
                </div>
                <CardContent className="p-6">
                  <div className="flex justify-between items-start mb-3">
                    <h3 className="text-xl font-playfair font-semibold">{perfume.name}</h3>
                    <span className="text-lg font-bold text-primary">{perfume.price}</span>
                  </div>
                  <p className="text-muted-foreground mb-4">{perfume.description}</p>
                  <div className="flex items-center gap-1 mb-4">
                    {[...Array(5)].map((_, i) => (
                      <Star key={i} className="h-4 w-4 fill-primary text-primary" />
                    ))}
                    <span className="text-sm text-muted-foreground ml-2">(4.8)</span>
                  </div>
                  </CardContent>
                </Link>
                <CardContent className="p-6 pt-0">
                  <Button
                    className="w-full"
                    variant="outline"
                    onClick={e => {
                      e.stopPropagation();
                      handleAddToCart(perfume.id);
                    }}
                  >
                    Add to Cart
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
          
          <div className="text-center mt-12">
            <Link to="/products">
              <Button size="lg" className="glow-effect">
                View All Products
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Why Choose Us */}
      <section className="py-24 bg-secondary/50">
        <div className="container mx-auto px-6">
          <div className="text-center mb-16">
            <h2 className="text-4xl md:text-5xl font-playfair font-bold mb-6 gradient-text">
              Why Choose EYES
            </h2>
          </div>
          
          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center stagger-animation">
              <div className="mb-6">
                <Sparkles className="h-12 w-12 text-primary mx-auto" />
              </div>
              <h3 className="text-xl font-playfair font-semibold mb-4">Premium Quality</h3>
              <p className="text-muted-foreground">
                Each fragrance is crafted with the finest ingredients sourced from around the world
              </p>
            </div>
            
            <div className="text-center stagger-animation" style={{animationDelay: '0.2s'}}>
              <div className="mb-6">
                <Gift className="h-12 w-12 text-primary mx-auto" />
              </div>
              <h3 className="text-xl font-playfair font-semibold mb-4">Unique Scents</h3>
              <p className="text-muted-foreground">
                Exclusive fragrances you won't find anywhere else, designed by master perfumers
              </p>
            </div>
            
            <div className="text-center stagger-animation" style={{animationDelay: '0.4s'}}>
              <div className="mb-6">
                <Heart className="h-12 w-12 text-primary mx-auto" />
              </div>
              <h3 className="text-xl font-playfair font-semibold mb-4">Crafted with Love</h3>
              <p className="text-muted-foreground">
                Every bottle is a labor of love, ensuring you receive the perfect fragrance experience
              </p>
            </div>
          </div>
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

export default Landing;