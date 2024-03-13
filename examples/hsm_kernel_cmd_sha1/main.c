#include <stdio.h>
#include "mbedtls/sha1.h"

// #define HSM_SOC
#ifdef HSM_SOC
#include "ns_libopt.h"

#define TIMEOUT_CYCLE           0x1fffff
#define MAILBOX_NUM             0
#define CMD_LEN                 20
#define CMD_NUM                 2
#define SHA1_RES_LEN            5

MAILBOX_TypeDef *CORE0_MAILBOX_ICOCP = ((MAILBOX_TypeDef *) (0x09000000UL));
volatile uint32_t hartid = 0;

uint32_t mailbox_in_addr = (0x09000000 + 0x2000 + MAILBOX_NUM*256);
uint32_t mailbox_out_addr = (0x09000000 + 0x2000 + MAILBOX_NUM*256);

uint32_t wBuf[64];
uint32_t rBuf[64];
uint32_t resBuf[64];

volatile uint8_t mailbox_in_it = 0;
volatile uint8_t mailbox_out_it = 0;

/**
 * \brief memory compare function
 *
 * \param src: source data pointer
 * \param dst: destination data pointer
 * \param length: the compare data length
 *
 * \retval ErrStatus: ERROR or SUCCESS
 */
ErrStatus MemoryCompare(uint32_t* src, uint32_t* dst, uint8_t length)
{
    uint32_t srcTemp, dstTemp;

    while (length--) {
        srcTemp = *src++;
        dstTemp = *dst++;
        if (srcTemp != dstTemp) {
            printf("len: %d, src: %x, dst: %x\r\n", length, srcTemp, dstTemp);
            return ERROR;
        }
    }
    return SUCCESS;
}

void CORE0_MAILBOX_IRQHandler(void)
{
    if (hartid == 0) {
        /* for kernel cpu, the status is mailbox in full */
        if (MAILBOX_GetITStatus(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTST_MBX0_IFRE << (MAILBOX_NUM*2)) != RESET) {
            MAILBOX_ClearITStatus(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTST_MBX0_IFRE << (MAILBOX_NUM*2));  
            // MAILBOX_ITConfig(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTEN_MBX0_IFRE << (MAILBOX_NUM*2), DISABLE);     
            mailbox_in_it = 1;
        }
        /* for kernel cpu, the status is mailbox out free */
        if (MAILBOX_GetITStatus(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTST_MBX0_DONE << (MAILBOX_NUM*2)) != RESET) { 
            MAILBOX_ClearITStatus(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTST_MBX0_DONE << (MAILBOX_NUM*2)); 
            // MAILBOX_ITConfig(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTEN_MBX0_DONE << (MAILBOX_NUM*2), DISABLE);       
            mailbox_out_it = 1;
        }

    }
}

int main(void)
{
    uint8_t i = 0;
    uint8_t cnt = 0;
    uint8_t status = 1;
    uint32_t timeout = 0;
    int32_t retVal = 0;
    static unsigned char sha1_test_buf[CMD_NUM][57] =
    {
        { "abc" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
    };
    static size_t sha1_test_buflen[CMD_NUM] =
    {
        3, 56
    };

    #ifdef MISC_HAS_CORE0_MAILBOX_HAS_CLK
    core0_mailbox_clk_en(ENABLE);
    #endif

    hartid = __RV_CSR_READ(CSR_MHARTID);
    printf("core%d start\r\n", hartid);
    delay_1ms(1);
    if (hartid == 0) {
        #ifdef MISC_HAS_CORE0_MAILBOX_RST
        core0_mailbox_set_rst(DISABLE);
        core0_mailbox_set_rst(ENABLE);
        #endif
        /* Set id_val & id_mask to let host work */
        MAILBOX_KernelInit(CORE0_MAILBOX_ICOCP, 1, 0, 0); 
        /* Let core1 run */      
        core1_stop_on_reset(DISABLE);
    } else {
        printf("hartid read err\n");
        return 0;
    }

    /* Global interrupt enable*/
    __enable_irq();
    /* register interrupt CORE0_MAILBOX_IRQn */
    retVal = ECLIC_Register_IRQ(CORE0_MAILBOX_INTERNAL_INTR_IRQ_IRQn, ECLIC_NON_VECTOR_INTERRUPT,
                                                ECLIC_LEVEL_TRIGGER, 1, 0,
                                                CORE0_MAILBOX_IRQHandler);
    if (retVal == -1) {
        simulation_fail();
        return 0;
    }
    MAILBOX_ITConfig(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTEN_MBX0_IFRE << (MAILBOX_NUM*2), ENABLE);
    MAILBOX_ITConfig(CORE0_MAILBOX_ICOCP, MAILBOX_RF_INTEN_MBX0_DONE << (MAILBOX_NUM*2), ENABLE);

    while (1) {

        for (i = 0; i < CMD_LEN; i++) {
            wBuf[i] = ((i+cnt) | ((i+cnt) << 8) | ((i+cnt) << 16) | ((i+cnt) << 24));
        }

        /* Wait enter mailbox in full interrupt triggered by host to writing command to mailbox in */
        while (0 == mailbox_in_it);
        mailbox_in_it = 0;

        /* Read out to compare */
        MAILBOX_ReadDataFromMailboxIn(CORE0_MAILBOX_ICOCP, MAILBOX_NUM, ADDR32P(mailbox_in_addr), rBuf, CMD_LEN);
        if (ERROR == MemoryCompare(wBuf, rBuf, CMD_LEN)) {
            status = 0;
        }

        if (1 == status) {
            printf("core0 num %d rev mail pass\n",cnt);
        } else {
            printf("core0 num %d rev mail fail\n",cnt);
        }

        /*do process*/
        //mbedtls hash
        mbedtls_sha1(sha1_test_buf[cnt], sha1_test_buflen[cnt], resBuf);

        /* Write command to mailbox in for host to read */
        MAILBOX_WriteDataToMailboxOut(CORE0_MAILBOX_ICOCP, MAILBOX_NUM, ADDR32P(mailbox_out_addr), resBuf, SHA1_RES_LEN);
        /* Wait enter mailbox out free interrupt triggered by host read out command from mailbox out and clear the full status */
        while (0 == mailbox_out_it);
        mailbox_out_it = 0;

        timeout = 0;
        cnt++;

        /* Wait for next mailbox CMD*/
        if ((CMD_NUM+1) == cnt) {
            cnt = 0;
            break;
        }
    }

    return 0;
}
#else
int main(void)
{
    printf("hsm_kernel_cmd_sha1 is only applicable to the SoC of the HSM subsystem that uses Mailbox IP!");
    return 0;
}
#endif