using System.Security.Cryptography;
namespace DPIUnlocker;
internal sealed class AesCounter : IDisposable
{
    private readonly Aes aes=Aes.Create();private readonly byte[] counter;private byte[] block=new byte[16];private int index=16;
    public AesCounter(byte[] key,byte[] iv){aes.Key=key;counter=(byte[])iv.Clone();}
    public byte[] Transform(ReadOnlySpan<byte> input)
    {
        byte[] result=new byte[input.Length];
        for(int i=0;i<input.Length;i++)
        {
            if(index==16){block=aes.EncryptEcb(counter,PaddingMode.None);for(int n=15;n>=0;n--)if(++counter[n]!=0)break;index=0;}
            result[i]=(byte)(input[i]^block[index++]);
        }
        return result;
    }
    public void Dispose()=>aes.Dispose();
}

