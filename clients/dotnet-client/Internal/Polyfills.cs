// =============================================================================
// Polyfill: System.Runtime.CompilerServices.IsExternalInit
// =============================================================================
// Derleyici, "init" setter'ları emit ederken bu sınıfın TYPE referansını
// modifreq olarak property'nin setter signature'ına gömer. Tip .NET 5+ runtime
// BCL'inde inbox'tır ancak netstandard2.0 surface'ında yer almaz; netstandard
// hedefli derlemede compile-time hata verir.
//
// Çözüm: Tipi kendi assembly'mizde "internal" olarak tanımlamak. Aynı tip
// adının başka bir assembly'de inbox olarak bulunması (örn. net8.0 runtime
// üzerinde çalışan netstandard2.0 binary) çakışma yaratmaz çünkü derleyici
// modifreq'i kendi assembly içindeki tipe bağlar.
//
// Bu dosya sadece netstandard2.0 derlemesi için aktif olur; modern .NET
// TFM'lerinde no-op (ifdef false → boş file).
// =============================================================================

#if NETSTANDARD2_0
namespace System.Runtime.CompilerServices
{
    /// <summary>
    /// Compiler-required shim for C# 9 <c>init</c> accessors on netstandard2.0.
    /// Do not reference directly.
    /// </summary>
    internal static class IsExternalInit
    {
    }
}
#endif
