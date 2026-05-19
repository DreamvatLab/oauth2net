using Microsoft.AspNetCore.Authentication;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace Microsoft.Extensions.DependencyInjection {
    internal class JsonDataSerializer<T> : IDataSerializer<T>
        where T : class
    {
        public byte[] Serialize(T model)
        {
            return JsonSerializer.SerializeToUtf8Bytes(model);
        }

        [return: MaybeNull]
        public T Deserialize(byte[] data)
        {
            return JsonSerializer.Deserialize<T>(data);
        }
    }
}