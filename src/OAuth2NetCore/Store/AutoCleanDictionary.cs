using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Timers;

namespace OAuth2NetCore.Store {
    internal class AutoCleanDictionary<TKey, TValue>
    {
        private readonly ConcurrentDictionary<TKey, AutoCleanDictionaryPayload<TValue>> _dic = new ConcurrentDictionary<TKey, AutoCleanDictionaryPayload<TValue>>();
        private readonly TimeSpan _duration;
        private readonly Timer _timer;

        public AutoCleanDictionary(int timerIntervalSeconds, int payloadDurationSeconds)
        {
            _duration = TimeSpan.FromSeconds(payloadDurationSeconds);
            _timer = new Timer(timerIntervalSeconds * 1000);
            _timer.Start();
            _timer.Elapsed += OnElapsed;
        }


        public void TryAdd(TKey key, TValue value)
        {
            _dic.TryAdd(key, new AutoCleanDictionaryPayload<TValue>(value, _duration));
        }

        public bool TryRemove(TKey key, out TValue value)
        {
            if (_dic.TryRemove(key, out var paylaod))
            {
                // Honor the payload's TTL even if the periodic sweep hasn't fired yet — otherwise
                // an authorization code could still be redeemed past its expiration window.
                if (DateTimeOffset.UtcNow >= paylaod.Expire)
                {
                    value = default;
                    return false;
                }
                value = paylaod.Payload;
                return true;
            }
            else
            {
                value = default;
                return false;
            }
        }

        private void OnElapsed(object sender, ElapsedEventArgs e)
        {
            var list = _dic.ToList();
            foreach (var kv in list)
            {
                if (DateTimeOffset.UtcNow >= kv.Value.Expire)
                {
                    _dic.TryRemove(kv.Key, out _);
#if DEBUG
                    Console.WriteLine("auth code: {0} cleared.", kv.Key);
#endif
                }
            }
        }
    }

    internal class AutoCleanDictionaryPayload<T>
    {
        public DateTimeOffset Expire { get; }
        public T Payload { get; }

        public AutoCleanDictionaryPayload(T payload, TimeSpan duration)
        {
            Payload = payload;
            Expire = DateTimeOffset.UtcNow.Add(duration);
        }
    }
}
