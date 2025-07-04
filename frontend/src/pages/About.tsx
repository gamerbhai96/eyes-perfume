import React from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { Sparkles, Heart, Gift } from 'lucide-react';

const About = () => (
  <div className="min-h-screen bg-background pt-24 pb-16">
    {/* Hero Section */}
    <section className="relative flex items-center justify-center py-16 bg-gradient-hero overflow-hidden">
      <div className="absolute inset-0 bg-[url('https://images.pexels.com/photos/965989/pexels-photo-965989.jpeg')] bg-cover bg-center opacity-10" />
      <div className="container mx-auto px-6 text-center relative z-10">
        <Sparkles className="h-14 w-14 text-primary mx-auto mb-6" />
        <h1 className="text-5xl md:text-6xl font-playfair font-bold mb-4 gradient-text">About EYES Perfume</h1>
        <p className="text-xl text-muted-foreground max-w-2xl mx-auto mb-6">
          Where every fragrance tells a story. Discover our passion for luxury, artistry, and the pursuit of the perfect scent.
        </p>
      </div>
    </section>

    {/* Brand Story */}
    <section className="container mx-auto px-6 py-16">
      <Card className="max-w-3xl mx-auto shadow-xl border-border/50 bg-background/80">
        <CardContent className="p-8 text-center">
          <h2 className="text-3xl font-playfair font-bold mb-4 gradient-text">Our Story</h2>
          <p className="text-lg text-muted-foreground mb-6">
            Founded with a vision to bring the world's most enchanting fragrances to your doorstep, EYES Perfume is a celebration of luxury, elegance, and individuality. Each bottle is crafted with the finest ingredients, inspired by memories, dreams, and the beauty of nature.
          </p>
          <p className="text-lg text-muted-foreground mb-6">
            Our artisans blend tradition and innovation, ensuring every scent is unique and unforgettable. We believe that a fragrance is more than just a scent—it's an experience, a statement, and a journey.
          </p>
        </CardContent>
      </Card>
    </section>

    {/* Mission & Values */}
    <section className="container mx-auto px-6 py-12">
      <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
        <Card className="text-center p-6">
          <CardContent>
            <Gift className="h-10 w-10 text-primary mx-auto mb-4" />
            <h3 className="text-xl font-playfair font-semibold mb-2">Our Mission</h3>
            <p className="text-muted-foreground">
              To inspire confidence and joy through the art of perfumery, delivering luxury experiences to every customer.
            </p>
          </CardContent>
        </Card>
        <Card className="text-center p-6">
          <CardContent>
            <Heart className="h-10 w-10 text-primary mx-auto mb-4" />
            <h3 className="text-xl font-playfair font-semibold mb-2">Our Values</h3>
            <p className="text-muted-foreground">
              Authenticity, craftsmanship, and a commitment to sustainability are at the heart of everything we do.
            </p>
          </CardContent>
        </Card>
        <Card className="text-center p-6">
          <CardContent>
            <Sparkles className="h-10 w-10 text-primary mx-auto mb-4" />
            <h3 className="text-xl font-playfair font-semibold mb-2">Why Choose Us?</h3>
            <p className="text-muted-foreground">
              We offer exclusive scents, exceptional service, and a passion for helping you find your signature fragrance.
            </p>
          </CardContent>
        </Card>
      </div>
    </section>
  </div>
);

export default About; 