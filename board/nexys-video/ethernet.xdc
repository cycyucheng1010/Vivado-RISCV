#-----------------------------------------------------------
#              Ethernet / RGMII                            -
#-----------------------------------------------------------

#set_property -dict { PACKAGE_PIN Y14   IOSTANDARD LVCMOS25 } [get_ports { eth_int_b }]; #IO_L6N_T0_VREF_13 Sch=eth_int_b
#set_property -dict { PACKAGE_PIN AA16  IOSTANDARD LVCMOS25 } [get_ports { eth_mdc }]; #IO_L1N_T0_13 Sch=eth_mdc
#set_property -dict { PACKAGE_PIN Y16   IOSTANDARD LVCMOS25 } [get_ports { eth_mdio }]; #IO_L1P_T0_13 Sch=eth_mdio
#set_property -dict { PACKAGE_PIN W14   IOSTANDARD LVCMOS25 } [get_ports { eth_pme_b }]; #IO_L6P_T0_13 Sch=eth_pme_b
set_property -dict { PACKAGE_PIN U7    IOSTANDARD LVCMOS33 SLEW SLOW DRIVE 4 } [get_ports { eth_rst_b }]; #IO_25_34 Sch=eth_rst_b
set_property -dict { PACKAGE_PIN V13   IOSTANDARD LVCMOS25 } [get_ports { rgmii_rxc }]; #IO_L13P_T2_MRCC_13 Sch=eth_rxck
set_property -dict { PACKAGE_PIN W10   IOSTANDARD LVCMOS25 } [get_ports { rgmii_rx_ctl }]; #IO_L10N_T1_13 Sch=eth_rxctl
set_property -dict { PACKAGE_PIN AB16  IOSTANDARD LVCMOS25 } [get_ports { rgmii_rd[0] }]; #IO_L2P_T0_13 Sch=eth_rxd[0]
set_property -dict { PACKAGE_PIN AA15  IOSTANDARD LVCMOS25 } [get_ports { rgmii_rd[1] }]; #IO_L4P_T0_13 Sch=eth_rxd[1]
set_property -dict { PACKAGE_PIN AB15  IOSTANDARD LVCMOS25 } [get_ports { rgmii_rd[2] }]; #IO_L4N_T0_13 Sch=eth_rxd[2]
set_property -dict { PACKAGE_PIN AB11  IOSTANDARD LVCMOS25 } [get_ports { rgmii_rd[3] }]; #IO_L7P_T1_13 Sch=eth_rxd[3]
set_property -dict { PACKAGE_PIN AA14  IOSTANDARD LVCMOS25 SLEW FAST DRIVE 16 } [get_ports { rgmii_txc }]; #IO_L5N_T0_13 Sch=eth_txck
set_property -dict { PACKAGE_PIN V10   IOSTANDARD LVCMOS25 SLEW FAST DRIVE 16 } [get_ports { rgmii_tx_ctl }]; #IO_L10P_T1_13 Sch=eth_txctl
set_property -dict { PACKAGE_PIN Y12   IOSTANDARD LVCMOS25 SLEW FAST DRIVE 16 } [get_ports { rgmii_td[0] }]; #IO_L11N_T1_SRCC_13 Sch=eth_txd[0]
set_property -dict { PACKAGE_PIN W12   IOSTANDARD LVCMOS25 SLEW FAST DRIVE 16 } [get_ports { rgmii_td[1] }]; #IO_L12N_T1_MRCC_13 Sch=eth_txd[1]
set_property -dict { PACKAGE_PIN W11   IOSTANDARD LVCMOS25 SLEW FAST DRIVE 16 } [get_ports { rgmii_td[2] }]; #IO_L12P_T1_MRCC_13 Sch=eth_txd[2]
set_property -dict { PACKAGE_PIN Y11   IOSTANDARD LVCMOS25 SLEW FAST DRIVE 16 } [get_ports { rgmii_td[3] }]; #IO_L11P_T1_SRCC_13 Sch=eth_txd[3]

create_clock -add -name rgmii_rxc_pin -period 8.00 -waveform {0 5} [get_ports rgmii_rxc]

set rx_clock [get_clocks -of_objects [get_ports rgmii_rxc]]
set tx_clock [get_clocks -of_objects [get_pins -hier clk_wiz_1/clk_out2]]
set main_clock [get_clocks -of_objects [get_pins -hier clk_wiz_0/clk_out1]]

set_clock_groups -asynchronous -group $rx_clock -group $tx_clock -group $main_clock

set_max_delay -from $main_clock -to $tx_clock -datapath_only 8.0
set_max_delay -from $tx_clock -to $main_clock -datapath_only 8.0

set_false_path -through [get_pins -hier Ethernet/async_resetn]
set_false_path -through [get_pins -hier Ethernet/interrupt]

