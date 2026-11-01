/**
 * Informer AI Voice Synthesis Engine using Web Speech API.
 */

class VoiceService {
  constructor() {
    this.synth = typeof window !== 'undefined' ? window.speechSynthesis : null;
    this.isMuted = false;
    this.isSpeaking = false;
  }

  isSupported() {
    return !!this.synth;
  }

  speak(text, onStart = null, onEnd = null) {
    if (!this.synth || this.isMuted || !text) return;

    this.stop();

    const utterance = new SpeechSynthesisUtterance(text);
    utterance.rate = 1.0;
    utterance.pitch = 1.0;
    utterance.lang = 'en-US';

    // Pick natural voice if available
    const voices = this.synth.getVoices();
    const preferred = voices.find(v => v.lang.startsWith('en') && (v.name.includes('Google') || v.name.includes('Natural') || v.name.includes('David') || v.name.includes('Zira')));
    if (preferred) {
      utterance.voice = preferred;
    }

    utterance.onstart = () => {
      this.isSpeaking = true;
      if (onStart) onStart();
    };

    utterance.onend = () => {
      this.isSpeaking = false;
      if (onEnd) onEnd();
    };

    utterance.onerror = () => {
      this.isSpeaking = false;
      if (onEnd) onEnd();
    };

    this.synth.speak(utterance);
  }

  stop() {
    if (this.synth) {
      this.synth.cancel();
      this.isSpeaking = false;
    }
  }

  toggleMute() {
    this.isMuted = !this.isMuted;
    if (this.isMuted) {
      this.stop();
    }
    return this.isMuted;
  }
}

export const voice = new VoiceService();
