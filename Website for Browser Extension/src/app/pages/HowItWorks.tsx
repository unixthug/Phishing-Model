import { Navigation } from '../components/Navigation';
import { Footer } from '../components/Footer';
import { Button } from '../components/ui/button';
import illustration from 'figma:asset/c17c99e05356c9e3f54e815b5fe5f3a18f5a00fa.png';
import screenshot1 from 'figma:asset/d7175991f3357b5897b9581bd0483e03afff1010.png';

export function HowItWorks() {
  return (
    <div className="min-h-screen bg-white flex flex-col">
      <Navigation />
      
      <main className="flex-1">
        {/* Hero Section */}
        <section className="container mx-auto px-6 py-16">
          <div className="grid lg:grid-cols-2 gap-12 items-center mb-20">
            <div>
              <h1 className="text-5xl font-bold text-gray-900 mb-6">
                How does RiskLens work?
              </h1>
              <p className="text-gray-600 text-lg leading-relaxed">
                RiskLens is an AI-powered browser extension that acts as a real-time safety scout for your web browsing. 
                Whenever you visit a website, it automatically analyzes various risk factors—such as the site's data breach 
                history, the presence of malicious trackers and cookies, unusual privacy policies, and suspicious behaviors 
                like excessive redirects. It then instantly synthesizes this information into a simple, easy-to-understand 
                risk score, which is displayed directly in your browser. This allows you to make informed choices about 
                which sites to trust and use. Here we'll go over step by step how to use RiskLens, exactly how it works, 
                and what you can do with it.
              </p>
            </div>
            <div className="flex justify-center">
              <img src={illustration} alt="RiskLens Illustration" className="w-64 h-64 object-contain" />
            </div>
          </div>

          {/* User Guide Section */}
          <div className="mb-20">
            <h2 className="text-3xl font-bold text-gray-900 mb-8">
              RiskLens' browser extension user guide
            </h2>
            
            <p className="text-gray-600 text-lg mb-8">
              To check whether the extension is installed, take a look at the top bar of your browser. If the extension 
              is active, you'll see the RiskLens icon
            </p>

            {/* Browser Screenshot */}
            <div className="mb-12 bg-gray-50 p-8 rounded-2xl">
              <img 
                src="https://images.unsplash.com/photo-1551650975-87deedd944c3?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxicm93c2VyJTIwZXh0ZW5zaW9uJTIwY2hyb21lfGVufDF8fHx8MTc3MTA0Mzk5OXww&ixlib=rb-4.1.0&q=80&w=1080"
                alt="Browser extension in toolbar" 
                className="w-full max-w-3xl mx-auto rounded-lg border border-gray-200"
              />
            </div>

            <p className="text-gray-600 text-lg mb-8">
              Once the extension is installed, when browsing different websites you should see a small window in the 
              corner of your browser letting you know how safe the website you're on is.
            </p>

            {/* Amazon Example Screenshot */}
            <div className="mb-12">
              <img 
                src={screenshot1}
                alt="RiskLens popup showing website safety rating" 
                className="w-full rounded-lg border border-gray-200"
              />
            </div>

            <p className="text-gray-600 text-lg">
              This will let you know if your website is trusted, risked, or dangerous. If you want a more detailed look 
              you can click the window to open a smaller version of our dashboard where you can see the websites risk score, 
              history, and reasoning for it's rating
            </p>
          </div>

          {/* Detailed Dashboard Section */}
          <div className="mb-20">
            <div className="bg-gray-50 rounded-2xl p-8">
              <img 
                src="https://images.unsplash.com/photo-1460925895917-afdab827c52f?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxkYXNoYm9hcmQlMjBhbmFseXRpY3N8ZW58MXx8fHwxNzcxMDQ0MDAwfDA&ixlib=rb-4.1.0&q=80&w=1080"
                alt="Detailed dashboard view" 
                className="w-full rounded-lg border border-gray-200 mb-8"
              />
              <p className="text-gray-600 text-lg">
                From here you can rate your experience, save the website to your dashboard, or be taken to our website 
                for a full in depth breakdown of the website, its saftey risks, safer alternatives, and more.
              </p>
            </div>
          </div>

          {/* Try It Section */}
          <div className="text-center py-16">
            <h2 className="text-4xl font-bold text-gray-900 mb-8">
              Try it for yourself.
            </h2>
            <Button className="bg-green-600 hover:bg-green-700 text-white rounded-full px-8 h-12 text-lg">
              Get a Demo →
            </Button>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
}
