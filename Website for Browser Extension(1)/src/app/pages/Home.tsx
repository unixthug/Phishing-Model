import { Navigation } from '../components/Navigation';
import { Hero } from '../components/Hero';
import { Features } from '../components/Features';
import { HowItWorks } from '../components/HowItWorks';
import { Objectives } from '../components/Objectives';
import { CTA } from '../components/CTA';
import { Footer } from '../components/Footer';

export function Home() {
  return (
    <div className="min-h-screen">
      <Navigation />
      <div id="home">
        <Hero />
      </div>
      <Features />
      <HowItWorks />
      <div id="roadmap">
        <Objectives />
      </div>
      <CTA />
      <Footer />
    </div>
  );
}
