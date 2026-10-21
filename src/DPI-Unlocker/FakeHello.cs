using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
namespace DPIUnlocker;
internal static class FakeHello
{
    private static readonly byte[] payload = Convert.FromHexString(
        "16030102a4010002a00303531b5b9735d271efc6c08b3cc02b031b8aafa9927d2eeba875776f66f6cacc5420adc823baefc13221e7a7326e2e595c7701b059eb689681299e1584eae0aa76ca0022130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100023500000013001100000e7777772e676f6f676c652e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b00020100002300000010000e000c02683208687474702f312e310005000501000000000022000a00080403050306030203001200000033006b0069001d002073d4ab37346437255e7e2066411d8fd7ccc66443219ecdfd868901285cc45d7f0017004104da2b8432221e30db3b1c62bda63323bc455a7e7bee17f57534b738385bfe4dd4c4407c968da02d9d3ac0fe4a9002fd57b5fa53ce976a89f9bf4642927e1f0185002b0009080304030303020301000d0018001604030503060308040805080604010501060102030201002d00020101001c00024001001b000706000100020003fe0d01190000010003c90020d6d1f94095d0b691ac9cb678b25dd6cd78ca9dc491948d0fc1032fb2b51dbb3d00efe8cdfea6dbe90e47ba2690aaf493fe8cba74bc2eba6ed661e8478b5132ae901d4d0b7facc3b84dd1381bfebd2ccb685ae546bf0c7792d2bd77b732b1e9ac50b4a75e7f76e544cdc44c5e3315d162661fb132b2480c0bf4485f34d23e072e815823ea926c2e2d231c6ef3e07a8f25da009c46f006ec8c56164090f3b6ba6df957c76eb1fc4a5f436ecb3faf6465e771fc19939f862307eb98c13afa1f5d394a8a7c3313294cccedc1b872de44e2d5620488349cadd325f68bd3b2d9938fd1dbdc4a54064daaae055bd19ffcbef9adf93036035fdd082209147ee018a7cdb626fb4ba2dcebeb5ed8c283a0ca891a6b7b");
    private const int OriginalSniIndex = 125;
    private const int OriginalSniLength = 14; // "www.google.com"

    public static byte[] Create(string? fakeSni = null)
    {
        if (string.IsNullOrEmpty(fakeSni) || fakeSni == "www.google.com")
            return (byte[])payload.Clone();

        byte[] sniBytes = Encoding.ASCII.GetBytes(fakeSni);
        int diff = sniBytes.Length - OriginalSniLength;

        byte[] result = new byte[payload.Length + diff];
        payload.AsSpan(0, 3).CopyTo(result);

        ushort newRecordLen = (ushort)(BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(3, 2)) + diff);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(3, 2), newRecordLen);

        result[5] = payload[5]; // handshake type 1 (ClientHello)

        int origHsLen = (payload[6] << 16) | (payload[7] << 8) | payload[8];
        int newHsLen = origHsLen + diff;
        result[6] = (byte)(newHsLen >> 16);
        result[7] = (byte)(newHsLen >> 8);
        result[8] = (byte)newHsLen;

        const int extsLenOffset = 114;
        payload.AsSpan(9, extsLenOffset - 9).CopyTo(result.AsSpan(9));

        ushort origExtsLen = BinaryPrimitives.ReadUInt16BigEndian(payload.AsSpan(extsLenOffset, 2));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(extsLenOffset, 2), (ushort)(origExtsLen + diff));

        // SNI extension header at 116: type 0x0000, ext_len, list_len, name_type, name_len
        result[116] = 0; result[117] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(118, 2), (ushort)(sniBytes.Length + 5));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(120, 2), (ushort)(sniBytes.Length + 3));
        result[122] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(123, 2), (ushort)sniBytes.Length);
        sniBytes.CopyTo(result, 125);

        payload.AsSpan(OriginalSniIndex + OriginalSniLength).CopyTo(result.AsSpan(125 + sniBytes.Length));
        return result;
    }
}

