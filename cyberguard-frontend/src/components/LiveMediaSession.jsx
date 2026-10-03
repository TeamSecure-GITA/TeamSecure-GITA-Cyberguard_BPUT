import { useCallback, useEffect, useRef, useState } from 'react';

const FRAME_INTERVAL_MS = 1000;

export default function LiveMediaSession({ apiBaseUrl, accessToken }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const streamRef = useRef(null);
  const socketRef = useRef(null);
  const timerRef = useRef(null);
  const processorRef = useRef(null);
  const audioContextRef = useRef(null);
  const audioSourceRef = useRef(null);
  const audioGainRef = useRef(null);
  const audioSamplesRef = useRef([]);
  const audioSampleCountRef = useRef(0);
  const pendingFrameRef = useRef(false);
  const pendingAudioRef = useRef(false);
  const mountedRef = useRef(true);
  const sessionGenerationRef = useRef(0);
  const [status, setStatus] = useState('idle');
  const [error, setError] = useState('');
  const [latest, setLatest] = useState(null);
  const [latestAudio, setLatestAudio] = useState(null);
  const [summary, setSummary] = useState(null);
  const [audioEnabled, setAudioEnabled] = useState(false);
  const [audioError, setAudioError] = useState('');

  const releaseMedia = useCallback(() => {
    if (timerRef.current) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (processorRef.current) {
      processorRef.current.onaudioprocess = null;
      processorRef.current.disconnect();
      processorRef.current = null;
    }
    audioSourceRef.current?.disconnect();
    audioSourceRef.current = null;
    audioGainRef.current?.disconnect();
    audioGainRef.current = null;
    if (audioContextRef.current && audioContextRef.current.state !== 'closed') {
      void audioContextRef.current.close();
    }
    audioContextRef.current = null;
    audioSamplesRef.current = [];
    audioSampleCountRef.current = 0;
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    if (videoRef.current) videoRef.current.srcObject = null;
  }, []);

  const makeAudioWav = useCallback((samples, sampleRate) => {
    const pcm = new ArrayBuffer(44 + samples.length * 2);
    const view = new DataView(pcm);
    const writeText = (offset, value) => {
      for (let index = 0; index < value.length; index += 1) view.setUint8(offset + index, value.charCodeAt(index));
    };
    writeText(0, 'RIFF');
    view.setUint32(4, 36 + samples.length * 2, true);
    writeText(8, 'WAVE');
    writeText(12, 'fmt ');
    view.setUint32(16, 16, true);
    view.setUint16(20, 1, true);
    view.setUint16(22, 1, true);
    view.setUint32(24, sampleRate, true);
    view.setUint32(28, sampleRate * 2, true);
    view.setUint16(32, 2, true);
    view.setUint16(34, 16, true);
    writeText(36, 'data');
    view.setUint32(40, samples.length * 2, true);
    for (let index = 0; index < samples.length; index += 1) {
      const clamped = Math.max(-1, Math.min(1, samples[index]));
      view.setInt16(44 + index * 2, clamped < 0 ? clamped * 0x8000 : clamped * 0x7fff, true);
    }
    return new Uint8Array(pcm);
  }, []);

  const sendAudioChunk = useCallback((socket, samples, sampleRate) => {
    if (!samples.length || socket.readyState !== WebSocket.OPEN || pendingAudioRef.current) return false;
    const targetSampleRate = Math.min(sampleRate, 16000);
    let pcmSamples = samples;
    if (sampleRate > targetSampleRate) {
      const outputLength = Math.floor(samples.length * targetSampleRate / sampleRate);
      pcmSamples = new Float32Array(outputLength);
      for (let index = 0; index < outputLength; index += 1) {
        const position = index * sampleRate / targetSampleRate;
        const left = Math.floor(position);
        const fraction = position - left;
        const right = Math.min(left + 1, samples.length - 1);
        pcmSamples[index] = samples[left] * (1 - fraction) + samples[right] * fraction;
      }
    }
    const wav = makeAudioWav(pcmSamples, targetSampleRate);
    let binary = '';
    const bytesPerSlice = 0x8000;
    for (let offset = 0; offset < wav.length; offset += bytesPerSlice) {
      binary += String.fromCharCode(...wav.subarray(offset, offset + bytesPerSlice));
    }
    socket.send(JSON.stringify({ type: 'audio', audio: btoa(binary) }));
    pendingAudioRef.current = true;
    return true;
  }, [makeAudioWav]);

  const flushAudioChunk = useCallback((socket) => {
    if (audioSampleCountRef.current === 0 || pendingAudioRef.current) return false;
    const samples = new Float32Array(audioSampleCountRef.current);
    let offset = 0;
    audioSamplesRef.current.forEach((part) => {
      samples.set(part, offset);
      offset += part.length;
    });
    audioSamplesRef.current = [];
    audioSampleCountRef.current = 0;
    const sampleRate = audioContextRef.current?.sampleRate || 48000;
    return sendAudioChunk(socket, samples, sampleRate);
  }, [sendAudioChunk]);

  const stopSession = useCallback(() => {
    sessionGenerationRef.current += 1;
    const socket = socketRef.current;
    flushAudioChunk(socket);
    releaseMedia();
    if (socket?.readyState === WebSocket.OPEN) {
      setStatus('stopping');
      socket.send(JSON.stringify({ type: 'stop' }));
    } else if (socket && socket.readyState < WebSocket.CLOSING) {
      socket.close();
      socketRef.current = null;
      setStatus('idle');
    } else {
      setStatus('idle');
    }
  }, [flushAudioChunk, releaseMedia]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      sessionGenerationRef.current += 1;
      releaseMedia();
      if (socketRef.current && socketRef.current.readyState < WebSocket.CLOSING) {
        socketRef.current.close();
      }
    };
  }, [releaseMedia]);

  const startSession = async () => {
    const sessionGeneration = sessionGenerationRef.current + 1;
    sessionGenerationRef.current = sessionGeneration;
    setError('');
    setAudioError('');
    setLatest(null);
    setLatestAudio(null);
    setSummary(null);
    setStatus('opening_camera');
    try {
      if (!accessToken) throw new Error('Sign in is required for live media analysis.');
      if (!navigator.mediaDevices?.getUserMedia) throw new Error('Camera access is unavailable. Use a secure browser context and allow camera access.');
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: audioEnabled ? { channelCount: 1, echoCancellation: false, noiseSuppression: false, autoGainControl: false } : false,
        video: { width: { ideal: 640 }, height: { ideal: 360 }, facingMode: 'user' },
      });
      if (!mountedRef.current || sessionGenerationRef.current !== sessionGeneration) {
        stream.getTracks().forEach((track) => track.stop());
        return;
      }
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }
      if (!mountedRef.current || sessionGenerationRef.current !== sessionGeneration) {
        releaseMedia();
        return;
      }
      const socketUrl = `${apiBaseUrl.replace(/^http/, 'ws')}/api/v1/ws/media`;
      const socket = new WebSocket(socketUrl, [accessToken, 'cyberguard.media.v1']);
      socketRef.current = socket;
      setStatus('connecting');

      socket.onmessage = async (event) => {
        let message;
        try {
          message = JSON.parse(event.data);
        } catch {
          setError('The media service returned an invalid response.');
          return;
        }
        if (message.type === 'ready') {
          setStatus('live');
          if (audioEnabled && stream.getAudioTracks().length) {
            try {
              const AudioContextClass = window.AudioContext || window.webkitAudioContext;
              if (!AudioContextClass) throw new Error('Web Audio is unavailable in this browser.');
              const context = new AudioContextClass();
              await context.resume();
              audioContextRef.current = context;
              const source = context.createMediaStreamSource(stream);
              const processor = context.createScriptProcessor(4096, 1, 1);
              const silentGain = context.createGain();
              silentGain.gain.value = 0;
              const targetSamples = context.sampleRate * 5;
              source.connect(processor);
              processor.connect(silentGain);
              silentGain.connect(context.destination);
              audioSourceRef.current = source;
              processorRef.current = processor;
              audioGainRef.current = silentGain;
              processor.onaudioprocess = (audioEvent) => {
                if (socket.readyState !== WebSocket.OPEN) return;
                const input = audioEvent.inputBuffer.getChannelData(0);
                let offset = 0;
                while (offset < input.length) {
                  const available = targetSamples - audioSampleCountRef.current;
                  const count = Math.min(available, input.length - offset);
                  audioSamplesRef.current.push(input.slice(offset, offset + count));
                  audioSampleCountRef.current += count;
                  offset += count;
                  if (audioSampleCountRef.current === targetSamples) {
                    if (pendingAudioRef.current) {
                      audioSamplesRef.current = [];
                      audioSampleCountRef.current = 0;
                      setAudioError('An audio segment was skipped because the previous segment is still being analyzed.');
                    } else {
                      flushAudioChunk(socket);
                    }
                  }
                }
              };
            } catch (audioStartError) {
              setAudioError(audioStartError.message || 'Microphone audio analysis could not start.');
              stream.getAudioTracks().forEach((track) => track.stop());
            }
          }
          timerRef.current = window.setInterval(() => {
            if (socket.readyState !== WebSocket.OPEN || pendingFrameRef.current) return;
            const video = videoRef.current;
            const canvas = canvasRef.current;
            if (!video?.videoWidth || !video?.videoHeight || !canvas) return;
            const scale = Math.min(1, 640 / video.videoWidth, 360 / video.videoHeight);
            canvas.width = Math.max(1, Math.round(video.videoWidth * scale));
            canvas.height = Math.max(1, Math.round(video.videoHeight * scale));
            canvas.getContext('2d')?.drawImage(video, 0, 0, canvas.width, canvas.height);
            const image = canvas.toDataURL('image/jpeg', 0.72).split(',', 2)[1];
            if (image) {
              pendingFrameRef.current = true;
              socket.send(JSON.stringify({ type: 'frame', image }));
            }
          }, FRAME_INTERVAL_MS);
        } else if (message.type === 'frame_result') {
          pendingFrameRef.current = false;
          setLatest(message);
          setSummary((current) => ({
            ...current,
            frames_analyzed: message.frame_number,
            highest_risk: Math.max(current?.highest_risk || 0, message.risk_score),
          }));
        } else if (message.type === 'audio_result') {
          pendingAudioRef.current = false;
          setLatestAudio(message);
          setSummary((current) => ({
            ...current,
            audio_chunks_analyzed: message.chunk_number,
            highest_audio_risk: Math.max(current?.highest_audio_risk || 0, message.risk_score),
          }));
        } else if (message.type === 'audio_error') {
          pendingAudioRef.current = false;
          audioSamplesRef.current = [];
          audioSampleCountRef.current = 0;
          setAudioError(message.error || 'A microphone audio segment could not be analyzed.');
        } else if (message.type === 'frame_error') {
          pendingFrameRef.current = false;
          setError(message.error || 'A camera frame could not be analyzed.');
          releaseMedia();
          if (socket.readyState === WebSocket.OPEN) {
            setStatus('stopping');
            socket.send(JSON.stringify({ type: 'stop' }));
          }
        } else if (['session_complete', 'session_limit', 'session_timeout'].includes(message.type)) {
          releaseMedia();
          setSummary(message);
          setStatus(message.type === 'session_complete' ? 'complete' : 'limited');
        }
      };
      socket.onerror = () => {
        setError('Live media connection failed. Check the backend connection and try again.');
        releaseMedia();
        setStatus('error');
      };
      socket.onclose = () => {
        releaseMedia();
        socketRef.current = null;
        pendingFrameRef.current = false;
        pendingAudioRef.current = false;
        setStatus((current) => ['complete', 'limited', 'error'].includes(current) ? current : 'idle');
      };
    } catch (startError) {
      releaseMedia();
      if (mountedRef.current && sessionGenerationRef.current === sessionGeneration) {
        setStatus('error');
        setError(startError.message || 'Camera session could not be started.');
      }
    }
  };

  const active = ['opening_camera', 'connecting', 'live', 'stopping'].includes(status);
  return (
    <section className="mb-4 rounded-xl border border-violet-800/60 bg-violet-950/15 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold text-violet-100">Live camera frame triage</div>
          <p className="mt-1 max-w-2xl text-[10px] text-slate-400">
            Sends one camera frame per second for up to five minutes. When explicitly enabled, microphone segments are scored separately. Media is analyzed in memory and not saved; this does not verify identity or measure audio/video synchronization or lip-sync.
          </p>
        </div>
        {active ? (
          <button type="button" onClick={stopSession} className="rounded-lg border border-rose-800 px-3 py-2 text-xs text-rose-200">Stop session</button>
        ) : (
          <button type="button" onClick={startSession} disabled={!accessToken} className="rounded-lg border border-violet-700 px-3 py-2 text-xs text-violet-100 disabled:opacity-40">
            {status === 'opening_camera' || status === 'connecting' ? 'Connecting...' : 'Start camera session'}
          </button>
        )}
      </div>
      {!active && (
        <label className="mt-3 flex items-start gap-2 text-[10px] text-slate-300">
          <input
            type="checkbox"
            checked={audioEnabled}
            onChange={(event) => setAudioEnabled(event.target.checked)}
            className="mt-0.5 accent-violet-500"
          />
          <span>Also grant microphone access and analyze up to five-second audio segments. Off by default. Audio is processed in memory and discarded.</span>
        </label>
      )}
      {active && (
        <video ref={videoRef} muted playsInline className="mt-3 max-h-48 rounded-lg border border-slate-700 bg-black" />
      )}
      <canvas ref={canvasRef} className="hidden" />
      {status === 'live' && <p className="mt-2 text-[10px] text-emerald-300">Live · camera frames and, when enabled, microphone audio are analyzed separately.</p>}
      {latest && (
        <div className="mt-3 rounded-lg border border-slate-700 bg-slate-900/70 p-3 text-xs text-slate-200">
          Frame {latest.frame_number} · risk {latest.risk_score}/99 · {latest.method}
          <p className="mt-1 text-[10px] text-slate-400">{latest.calibration}</p>
          {(latest.reasons || []).map((reason) => <p key={reason} className="mt-1 text-[10px] text-slate-400">{reason}</p>)}
        </div>
      )}
      {active && audioEnabled && <p className="mt-2 text-[10px] text-violet-200">Microphone capture enabled · raw audio is not saved.</p>}
      {latestAudio && (
        <div className="mt-3 rounded-lg border border-slate-700 bg-slate-900/70 p-3 text-xs text-slate-200">
          Audio segment {latestAudio.chunk_number} · {latestAudio.duration_seconds}s · risk {latestAudio.risk_score}/99 · {latestAudio.method}
          <p className="mt-1 text-[10px] text-slate-400">{latestAudio.calibration}</p>
          {(latestAudio.reasons || []).map((reason) => <p key={reason} className="mt-1 text-[10px] text-slate-400">{reason}</p>)}
        </div>
      )}
      {summary && <p className="mt-2 text-[10px] text-slate-300">Session summary · {summary.frames_analyzed || 0} frames (peak {summary.highest_risk || 0}/99){audioEnabled ? ` · ${summary.audio_chunks_analyzed || 0} audio segments (peak ${summary.highest_audio_risk || 0}/99)` : ''}.</p>}
      {audioError && <p role="status" className="mt-2 text-[10px] text-amber-200">{audioError}</p>}
      {error && <p role="alert" className="mt-2 text-[10px] text-rose-300">{error}</p>}
      {['complete', 'limited', 'error'].includes(status) && !error && <p className="mt-2 text-[10px] text-amber-200">{status === 'complete' ? 'Session stopped.' : 'Session limit reached.'} Results are uncalibrated triage, not proof of authenticity or manipulation.</p>}
    </section>
  );
}
