use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

//TODO: add documentation (none)
pub fn append_leading_zeros(data: &[u8], bits_length: usize) -> Vec<u8> {
    if data.len() * 8 > bits_length {
        return data.to_vec();
    }

    let leading_zeros = if bits_length % 8 > 0 {
        vec![0; bits_length / 8 - data.len() + 1]
    } else {
        vec![0; bits_length / 8 - data.len()]
    };

    [&leading_zeros[..], &data].concat()
}

//TODO: check documentation (bn - no context)
/// Transforms slice into Bignum and right-shifts it by len(data)-qlen bits.
pub fn bits2int(data: &[u8], qlen: usize) -> Result<BigNum, ErrorStack> {
    let data_len_bits = data.len() * 8;
    let result = BigNum::from_slice(data).and_then(|data_bn| {
        if data_len_bits > qlen {
            let mut truncated = BigNum::new()?;
            truncated.rshift(&data_bn, (data_len_bits - qlen) as i32)?;

            Ok(truncated)
        } else {
            Ok(data_bn)
        }
    })?;
    let _data2 = data.to_vec();
    let _data_vec = result.to_vec();

    Ok(result)
}

//TODO: add documentation (bn - context: bn_ctx, order, qlen)
pub fn bits2octets(
    data: &[u8],
    length: usize,
    order: &BigNum,
    bn_ctx: &mut BigNumContext,
) -> Result<Vec<u8>, ErrorStack> {
    //FIXME: TO DECIDE WHETHER FOLLOW DIFFERENT TEST VECTORS (qlen for both cases)
    //    let z1 = match ctx.cipher_suite {
    //        CipherSuite::P256_SHA256_TAI => bits2int(data, data.len() * 8)?,
    //        CipherSuite::K163_SHA256_TAI => bits2int(data, ctx.qlen)?,
    //    };
    let z1 = bits2int(data, length)?;
    let result = BigNum::new().and_then(|mut res| {
        res.nnmod(&z1, order, bn_ctx)?;
        Ok(res.to_vec())
    })?;

    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bits2int() {
        let data1 = vec![0x01; 32];
        let data1_bn = BigNum::from_slice(&data1).unwrap();
        let result1 = bits2int(&data1, 256).unwrap();
        assert_eq!(data1_bn, result1);

        let data2 = vec![0x01; 33];
        let data2_bn = BigNum::from_slice(&data2).unwrap();
        let result2 = bits2int(&data2, 256).unwrap();
        let mut truncated = BigNum::new().unwrap();
        truncated.rshift(&data2_bn, 8).unwrap();
        assert_eq!(truncated.to_vec(), result2.to_vec());
    }
}
