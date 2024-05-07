#include <xmhf.h>

#define ALIGN_UP(n, boundary)	(((n)+((boundary)-1))&(~((boundary)-1)))

/// @brief Return the number of 4K memory pages can store the given number of bits <x>. This calculation needs to align
/// up x to 32K first. For example, if x is 31K or 32K bits in total, we can store all bits in 1 page. If x is 32K+1 
/// bits, we need to store all of them in 2 pages.
#define BITS_TO_PAGES_ALIGN_UP(x)	(size_t)(((uint64_t)((ALIGN_UP(x, (1 << (PAGE_SHIFT_4K + BITS_PER_BYTE_SHIFT)))) >> (uint64_t)BITS_PER_BYTE_SHIFT)) >> PAGE_SHIFT_4K)

XMHF_STL_BITMAP* xmhfstl_bitmap_create(uint32_t num_bits)
{
	XMHF_STL_BITMAP* result = NULL;
	ulong_t num_pages = 0;

	result = (XMHF_STL_BITMAP*)xmhf_mm_malloc(sizeof(XMHF_STL_BITMAP));
	if(!result)
		goto err;

	// TODO: change num_bits's type to ulong_t, then remove type cast
	num_pages = BITS_TO_PAGES_ALIGN_UP(num_bits);
	result->max_bits = num_bits;
	result->mem_table = (uint8_t**)xmhf_mm_malloc(num_pages * sizeof(uint8_t*));
	if(!result->mem_table)
		goto err;

	result->bits_stat = (uint16_t*)xmhf_mm_malloc(num_pages * sizeof(uint16_t));
	if(!result->bits_stat)
		goto err;

	return result;

err:
    if(result)
        xmhfstl_bitmap_destroy(result);
    return NULL;
}

void xmhfstl_bitmap_destroy(XMHF_STL_BITMAP* bitmap)
{
	ulong_t num_pages;
	ulong_t i = 0;

	if(!bitmap)
		return;

	// TODO: change bitmap->max_bits's type to ulong_t, then remove type cast
	num_pages = BITS_TO_PAGES_ALIGN_UP(bitmap->max_bits);
	for(i = 0; i < num_pages; i++)
	{
		uint8_t* mem = bitmap->mem_table[i];

		if(mem)
		{
			xmhf_mm_free(mem);
			mem = NULL;
		}
	}

	if(bitmap->mem_table)
	{
		xmhf_mm_free(bitmap->mem_table);
		bitmap->mem_table = NULL;
	}

	if(bitmap->bits_stat)
	{
		xmhf_mm_free(bitmap->bits_stat);
		bitmap->bits_stat = NULL;
	}

	xmhf_mm_free(bitmap);
}

bool xmhfstl_bitmap_set_bit(XMHF_STL_BITMAP* bitmap, const uint32_t bit_idx)
{
	uint32_t bit_offset;
	uint32_t byte_offset;
	uint32_t pg_offset;
	uint32_t bits_stat;
	uint8_t test_bit;

	// Sanity check
	if(!bitmap)
		return false;

	if(bit_idx >= bitmap->max_bits)
		return false;

	bit_offset = bit_idx % BITS_PER_BYTE;
	byte_offset = BITS_TO_BYTES(bit_idx) % PAGE_SIZE_4K;
	pg_offset = BITS_TO_BYTES(bit_idx) >> PAGE_SHIFT_4K;

	bits_stat = bitmap->bits_stat[pg_offset];

	if(!bits_stat)
	{
        if(!bitmap->mem_table[pg_offset]) 
        {
            // There is no page to hold the bitmap content
            bitmap->mem_table[pg_offset] = (uint8_t*) xmhf_mm_malloc_align(PAGE_SIZE_4K, PAGE_SIZE_4K);
            if(!bitmap->mem_table[pg_offset])
                return false;
        }
	}

	test_bit = bitmap->mem_table[pg_offset][byte_offset];
	if(test_bit & (1 << bit_offset))
		return true;  // already set
	else
    {
		bitmap->mem_table[pg_offset][byte_offset] = (uint8_t)(test_bit | (1 << bit_offset));
	    bitmap->bits_stat[pg_offset] = bits_stat + 1;
    }

	return true;
}


bool xmhfstl_bitmap_clear_bit(XMHF_STL_BITMAP* bitmap, const uint32_t bit_idx)
{
	uint32_t bit_offset;
	uint32_t byte_offset;
	uint32_t pg_offset;
	uint32_t bits_stat;
	uint8_t test_bit;

	// Sanity check
	if(!bitmap)
		return false;

	if(bit_idx >= bitmap->max_bits)
		return false;

	bit_offset = bit_idx % BITS_PER_BYTE;
	byte_offset = BITS_TO_BYTES(bit_idx) % PAGE_SIZE_4K;
	pg_offset = BITS_TO_BYTES(bit_idx) >> PAGE_SHIFT_4K;
	bits_stat = bitmap->bits_stat[pg_offset];

	if(!bits_stat)
		return true;

	test_bit = bitmap->mem_table[pg_offset][byte_offset];
	if(test_bit & (1 << bit_offset))
	{
		// The bit is set, so we need to clear it in the next
		bitmap->mem_table[pg_offset][byte_offset] = (uint8_t)(test_bit & ~(1 << bit_offset));
		bitmap->bits_stat[pg_offset] = bits_stat - 1;
        bits_stat = bitmap->bits_stat[pg_offset];
	}

	if(!bits_stat && bitmap->mem_table[pg_offset])
	{
		// There is no page to hold the xmhfstl_bitmap content
		xmhf_mm_free(bitmap->mem_table[pg_offset]);
		bitmap->mem_table[pg_offset] = NULL;
	}

	return true;
}

int xmhfstl_bitmap_is_bit_set(XMHF_STL_BITMAP* bitmap, const uint32_t bit_idx)
{
	uint32_t bit_offset;
	uint32_t byte_offset;
	uint32_t pg_offset;

    if(bit_idx >= bitmap->max_bits)
		return -1;

	bit_offset = bit_idx % BITS_PER_BYTE;
	byte_offset = BITS_TO_BYTES(bit_idx) % PAGE_SIZE_4K;
	pg_offset = BITS_TO_BYTES(bit_idx) >> PAGE_SHIFT_4K;

    // <mem_table> is not created because no bit is set in that page. So return false.
	if( !bitmap->mem_table[pg_offset])
		return 0;

	if(bitmap->mem_table[pg_offset][byte_offset] & (1 << bit_offset))
		return 1;
	else
		return 0;
}

int xmhfstl_bitmap_is_bit_clear(XMHF_STL_BITMAP* bitmap, const uint32_t bit_idx)
{
	uint32_t bit_offset;
	uint32_t byte_offset;
	uint32_t pg_offset;

    if(bit_idx >= bitmap->max_bits)
		return -1;

	bit_offset = bit_idx % BITS_PER_BYTE;
	byte_offset = BITS_TO_BYTES(bit_idx) % PAGE_SIZE_4K;
	pg_offset = BITS_TO_BYTES(bit_idx) >> PAGE_SHIFT_4K;

    // <mem_table> is not created because no bit is set in that page. So return true.
	if(!bitmap->mem_table[pg_offset])
		return 1;

	if(bitmap->mem_table[pg_offset][byte_offset] & (1 << bit_offset))
		return 0;
	else
		return 1;
}
