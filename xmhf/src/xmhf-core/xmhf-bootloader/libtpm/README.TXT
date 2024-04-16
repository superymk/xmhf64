libtpm - generic TPM functionality
==================================

libtpm contains generic TPM functionality (e.g., read/extend pcrs,
seal/unseal etc.). It is designed to be used with an environment 
specific TPM driver that is in charge of setting up and
preparing the TPM for operations. The driver needs to 
provide the following two function definitions for libtpm
to communicate with the physical TPM:

uint32_t tpm_wait_cmd_ready(uint32_t locality);


uint32_t tpm_write_cmd_fifo(uint32_t locality, uint8_t *in,
                                   uint32_t in_size, uint8_t *out,
                                   uint32_t *out_size);

Miao Yu (superymk): Create a separate copy of libtpm in xmhf-bootloader/secureloader/runtime because they use different
TPM functions. For example, xmhf-bootloader and xmhf-secureloader only needs to extend PCR, while xmhf-runtime needs to
enable hypapps to access NVRAM.