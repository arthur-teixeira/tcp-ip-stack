use std::net::Ipv4Addr;

fn sum_words(data: &[u8], skipword: usize) -> u32 {
    let len = data.len();
    let mut cur_data = &data[..];
    let mut sum = 0u32;
    let mut i = 0;

    while cur_data.len() >= 2 {
        if i != skipword {
            sum += u16::from_be_bytes(cur_data[0..2].try_into().unwrap()) as u32;
        }
        cur_data = &cur_data[2..];
        i += 1;
    }

    if i != skipword && len & 1 != 0 {
        sum += (data[len - 1] as u32) << 8;
    }

    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

pub fn calculate_checksum(data: &[u8], skipword: usize) -> u16 {
    if data.len() == 0 {
        return 0;
    }

    let mut sum = sum_words(data, skipword);

    finalize_checksum(sum)
}

fn ipv4_word_sum(w: &Ipv4Addr) -> u32 {
    let octets = w.octets();
    ((octets[0] as u32) << 8 | octets[1] as u32) + ((octets[2] as u32) << 8 | octets[3] as u32)
}

pub fn ipv4_checksum(
    data: &[u8],
    skipword: usize,
    source: &Ipv4Addr,
    destination: &Ipv4Addr,
    next_level_protocol: u8,
) -> u16 {
    let mut sum = 0u32;

    sum += ipv4_word_sum(source);
    sum += ipv4_word_sum(destination);
    sum += next_level_protocol as u32;
    sum += data.len() as u32;
    sum += sum_words(data, skipword);

    finalize_checksum(sum)
}
