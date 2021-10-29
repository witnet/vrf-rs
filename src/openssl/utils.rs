use openssl::{
    bn::{BigNum, BigNumContext},
    error::ErrorStack,
};

/// Appends leading zeros if provided slice is smaller than given length.
///
/// # Arguments
///
/// * `data`         - A slice of octets.
/// * `bits_length`  - An integer to specify the total length (in bits) after appending zeros.
///
/// # Returns
///
/// * A vector of octets with leading zeros (if necessary)
pub fn append_leading_zeros(data: &[u8], bits_length: usize) -> Vec<u8> {
    if data.len() * 8 > bits_length {
        return data.to_vec();
    }

    let leading_zeros = if bits_length % 8 > 0 {
        vec![0; bits_length / 8 - data.len() + 1]
    } else {
        vec![0; bits_length / 8 - data.len()]
    };

    [&leading_zeros[..], data].concat()
}

/// Converts a slice of octets into a `BigNum` of length `qlen` as specified in [RFC6979](https://tools.ietf.org/html/rfc6979)
/// (section 2.3.2).
///
/// # Arguments
///
/// * `data` - A slice representing the number to be converted.
/// * `qlen` - The desired length for the output `BigNum`.
///
/// # Returns
///
/// * If successful, a `BigNum` representing the conversion.
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

/// Transform an input to a sequence of `length` (in bits) and output this sequence representing a
/// number between 0 and `order` (non-inclusive), as specified in [RFC6979](https://tools.ietf.org/html/rfc6979) (section 2.3.4.).
///
/// # Arguments
///
/// * `data`         - A slice of octets.
/// * `bits_length`  - An integer to specify the total length (in bits) after appending zeros.
///
/// # Returns
///
/// * If successful, a vector of octets.
pub fn bits2octets(
    data: &[u8],
    length: usize,
    order: &BigNum,
    bn_ctx: &mut BigNumContext,
) -> Result<Vec<u8>, ErrorStack> {
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
        let expected_result_1 = BigNum::from_slice(&data1).unwrap();
        let result1 = bits2int(&data1, 256).unwrap();
        assert_eq!(result1, expected_result_1);

        let data2 = vec![0x01; 33];
        let data2_bn = BigNum::from_slice(&data2).unwrap();
        let result2 = bits2int(&data2, 256).unwrap();
        let mut expected_result_2 = BigNum::new().unwrap();
        expected_result_2.rshift(&data2_bn, 8).unwrap();

        assert_eq!(result2.to_vec(), expected_result_2.to_vec());
    }

    /// Test vector taken from [RFC6979](https://tools.ietf.org/html/rfc6979)
    /// Input: `sha256("sample")`
    /// `qlen=163`
    #[test]
    fn test_bits2octets() {
        let data = hex::decode("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF")
            .unwrap();
        let order_hex = hex::decode("04000000000000000000020108A2E0CC0D99F8A5EF").unwrap();
        let order = BigNum::from_slice(&order_hex.as_slice()).unwrap();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let result = bits2octets(
            &data.as_slice(),
            order.num_bits() as usize,
            &order,
            &mut bn_ctx,
        )
        .unwrap();

        let expected_result = hex::decode("01795EDF0D54DB760F156D0DAC04C0322B3A204224").unwrap();
        assert_eq!(result, expected_result);
    }
}
