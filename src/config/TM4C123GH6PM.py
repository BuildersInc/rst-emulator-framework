from dataclasses import dataclass


@dataclass
class GPIO:
    BASE: int
    DATA: int = 0x00
    DIR: int = 0x00
    IS: int = 0x00
    IBE: int = 0x00
    IEV: int = 0x00
    IM: int = 0x00
    RIS: int = 0x00
    MIS: int = 0x00
    AFSEL: int = 0x00
    DR2R: int = 0x00
    DR4R: int = 0x00
    DR8R: int = 0x00
    ODR: int = 0x00
    PUR: int = 0x00
    PDR: int = 0x00
    SLR: int = 0x00
    DEN: int = 0x00
    LOCK: int = 0x00
    CR: int = 0x00
    AMSEL: int = 0x00
    PCTL: int = 0x00
    ADCCTL: int = 0x00
    MACTL: int = 0x00
    PERIPHID4: int = 0x00
    PERIPHID5: int = 0x00
    PERIPHID6: int = 0x00
    PERIPHID7: int = 0x00
    PERIPHID0: int = 0x00
    PERIPHID1: int = 0x00
    PERIPHID2: int = 0x00
    PERIPHID3: int = 0x00
    CELLID0: int = 0x00
    CELLID1: int = 0x00
    CELLID2: int = 0x00
    CELLID3: int = 0x00

    def __post_init__(self):
        self.DATA = self.BASE + 0x3FC
        self.DIR = self.BASE + 0x400
        self.IS = self.BASE + 0x404
        self.IBE = self.BASE + 0x408
        self.IEV = self.BASE + 0x40C
        self.IM = self.BASE + 0x410
        self.RIS = self.BASE + 0x414
        self.MIS = self.BASE + 0x41C
        self.AFSEL = self.BASE + 0x420
        self.DR2R = self.BASE + 0x500
        self.DR4R = self.BASE + 0x504
        self.DR8R = self.BASE + 0x508
        self.ODR = self.BASE + 0x50C
        self.PUR = self.BASE + 0x510
        self.PDR = self.BASE + 0x514
        self.SLR = self.BASE + 0x518
        self.DEN = self.BASE + 0x51C
        self.LOCK = self.BASE + 0x520
        self.CR = self.BASE + 0x524
        self.AMSEL = self.BASE + 0x528
        self.PCTL = self.BASE + 0x52C
        self.ADCCTL = self.BASE + 0x530
        self.MACTL = self.BASE + 0x534
        self.PERIPHID4 = self.BASE + 0xFD0
        self.PERIPHID5 = self.BASE + 0xFD4
        self.PERIPHID6 = self.BASE + 0xFD8
        self.PERIPHID7 = self.BASE + 0xFDC
        self.PERIPHID0 = self.BASE + 0xFE0
        self.PERIPHID1 = self.BASE + 0xFE4
        self.PERIPHID2 = self.BASE + 0xFE8
        self.PERIPHID3 = self.BASE + 0xFEC
        self.CELLID0 = self.BASE + 0xFF0
        self.CELLID1 = self.BASE + 0xFF4
        self.CELLID2 = self.BASE + 0xFF8
        self.CELLID3 = self.BASE + 0xFFC


APB_GPIO_PORT_A = GPIO(0x40004000)
AHB_GPIO_PORT_A = GPIO(0x40058000)

APB_GPIO_PORT_B = GPIO(0x40005000)
AHB_GPIO_PORT_B = GPIO(0x40059000)

APB_GPIO_PORT_C = GPIO(0x40006000)
AHB_GPIO_PORT_C = GPIO(0x4005A000)

APB_GPIO_PORT_D = GPIO(0x40007000)
AHB_GPIO_PORT_D = GPIO(0x4005B000)

APB_GPIO_PORT_E = GPIO(0x40024000)
AHB_GPIO_PORT_E = GPIO(0x4005C000)

APB_GPIO_PORT_F = GPIO(0x40025000)
AHB_GPIO_PORT_F = GPIO(0x4005D000)

RCGC_GPIO_R = 0x400FE608
