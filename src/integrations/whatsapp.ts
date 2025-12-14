export interface WhatsAppAdapter {
  sendMessage(to: string, message: string): Promise<void>;
}

class MockWhatsAppAdapter implements WhatsAppAdapter {
  async sendMessage(to: string, message: string): Promise<void> {
    console.log(`[Mock WhatsApp] -> ${to}: ${message}`);
  }
}

export const whatsappAdapter: WhatsAppAdapter = new MockWhatsAppAdapter();
