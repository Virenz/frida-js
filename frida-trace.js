// traceAddr(addr)
// ---------------------------------------------------------------------------------------
let moduleBase;
let pre_regs = [];
let infoMap = new Map();
let detailInsMap = new Map();
let regs_map = new Map();

function formatArm64Regs(context) {
    let regs = []
    regs.push(context.x0);
    regs.push(context.x1);
    regs.push(context.x2);
    regs.push(context.x3);
    regs.push(context.x4);
    regs.push(context.x5);
    regs.push(context.x6);
    regs.push(context.x7);
    regs.push(context.x8);
    regs.push(context.x9);
    regs.push(context.x10);
    regs.push(context.x11);
    regs.push(context.x12);
    regs.push(context.x13);
    regs.push(context.x14);
    regs.push(context.x15);
    regs.push(context.x16);
    regs.push(context.x17);
    regs.push(context.x18);
    regs.push(context.x19);
    regs.push(context.x20);
    regs.push(context.x21);
    regs.push(context.x22);
    regs.push(context.x23);
    regs.push(context.x24);
    regs.push(context.x25);
    regs.push(context.x26);
    regs.push(context.x27);
    regs.push(context.x28);
    regs.push(context.fp);
    regs.push(context.lr);
    regs.push(context.sp);
    regs.push(context.pc);
    regs_map.set('x0', context.x0);
    regs_map.set('x1', context.x1);
    regs_map.set('x2', context.x2);
    regs_map.set('x3', context.x3);
    regs_map.set('x4', context.x4);
    regs_map.set('x5', context.x5);
    regs_map.set('x6', context.x6);
    regs_map.set('x7', context.x7);
    regs_map.set('x8', context.x8);
    regs_map.set('x9', context.x9);
    regs_map.set('x10', context.x10);
    regs_map.set('x11', context.x11);
    regs_map.set('x12', context.x12);
    regs_map.set('x13', context.x13);
    regs_map.set('x14', context.x14);
    regs_map.set('x15', context.x15);
    regs_map.set('x16', context.x16);
    regs_map.set('x17', context.x17);
    regs_map.set('x18', context.x18);
    regs_map.set('x19', context.x19);
    regs_map.set('x20', context.x20);
    regs_map.set('x21', context.x21);
    regs_map.set('x22', context.x22);
    regs_map.set('x23', context.x23);
    regs_map.set('x24', context.x24);
    regs_map.set('x25', context.x25);
    regs_map.set('x26', context.x26);
    regs_map.set('x27', context.x27);
    regs_map.set('x28', context.x28);
    regs_map.set('fp', context.fp);
    regs_map.set('lr', context.lr);
    regs_map.set('sp', context.sp);
    regs_map.set('pc', context.pc);
    return regs;
}

function getRegsString(index) {
    let reg;
    if (index === 31) {
        reg = "sp"
    } else {
        reg = "x" + index;
    }
    return reg;
}

function isRegsChange(context, ins) {
    let currentRegs = formatArm64Regs(context);
    let entity = {};
    let logInfo = "";
    // 打印寄存器信息
    for (let i = 0; i < 32; i++) {
        if (i === 30) {
            continue
        }
        let preReg = pre_regs[i] ? pre_regs[i] : 0x0;
        let currentReg = currentRegs[i];
        if (Number(preReg) !== Number(currentReg)) {
            if (logInfo === "") {
                //尝试读取string
                let changeString = "";
                try {
                    let nativePointer = new NativePointer(currentReg);
                    changeString = nativePointer.readCString();
                } catch (e) {
                    changeString = "";
                }
                if (changeString !== "") {
                    currentReg = currentReg + " (" + changeString + ")";
                }
                logInfo = " " + getRegsString(i) + ": " + preReg + " --> " + currentReg + ", ";
            } else {
                logInfo = logInfo + " " + getRegsString(i) + ": " + preReg + " --> " + currentReg + ", ";
            }
        }
    }
    
    entity.info = logInfo;
    pre_regs = currentRegs;
    return entity;
}

function stalkerTraceRange(tid, base, size, offsetAddr) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const startAddress = instruction.address;
            const isModuleCode = startAddress.compare(base) >= 0 &&
                startAddress.compare(base.add(size)) < 0;
            do {
                iterator.keep();
                if (isModuleCode) {
                    let lastInfo = '[' + ptr(instruction["address"] - base) + ']' + '\t' + ptr(instruction["address"]) + '\t' + (instruction+';').padEnd(30,' ');
                    let address = instruction.address - base;
                    detailInsMap.set(String(address), JSON.stringify(instruction));
                    infoMap.set(String(address), lastInfo);

                    iterator.putCallout((context) => {
                        let offset = Number(context.pc) - base;
                        let detailIns = detailInsMap.get(String(offset));
                        
                        let insinfo = infoMap.get(String(offset));
                        let entity = isRegsChange(context, detailIns);
                        let info = insinfo + '\t#' + entity.info;

                        let next_pc = context.pc.add(4);
                        let insn_next = Instruction.parse(next_pc);
                        insinfo = '[' + ptr(insn_next["address"] - base) + ']' + '\t' + ptr(insn_next["address"]) + '\t' + (insn_next + ';').padEnd(30,' ');
                        let mnemonic = insn_next.mnemonic;
                        if (mnemonic.startsWith("b.") || mnemonic === "b" || mnemonic === "bl" || mnemonic === "br" ||  mnemonic === "bx" || mnemonic.startsWith("bl") || mnemonic.startsWith("bx")) {
                            info = info + '\n' + insinfo + '\t#';
                        }
                        console.log(info);
                    });
                }
            } while (iterator.next() !== null);
        }
    })
}

function traceAddr(addr,base_addr) {
    let moduleMap = new ModuleMap();
    let targetModule = moduleMap.find(addr);

    console.log('-----start trace：', addr, '------');
    moduleBase = base_addr;
    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId()
            stalkerTraceRange(this.tid,targetModule.base,targetModule.size,addr);
        },
        onLeave: function(ret) {
            Stalker.unfollow(this.tid);
            Stalker.garbageCollect();
            console.log('ret: ' + ret);
            console.log('-----end trace------');
        }
    });
}
// ---------------------------------------------------------------------------------------

// traceNativeFunction
// ---------------------------------------------------------------------------------------
// 打印调用堆栈
function traceFunction(addr, base_addr){
    
    let moduleMap = new ModuleMap();
    let base_size = moduleMap.find(addr).size;

    Interceptor.attach(addr, {
        onEnter: function(args) {
            this.tid = Process.getCurrentThreadId();
            Stalker.follow(this.tid, {
                events: {
                    call: true
                },
                onReceive: function(events) {
                    let allEvents = Stalker.parse(events);
                    let first_depth = 0;
                    let is_first = true;
                    for (let i = 0; i < allEvents.length; i++) {
                        // 调用的流程, location是哪里发生的调用, target是调用到了哪里
                        if (allEvents[i][0] === "call") {
                            let location = allEvents[i][1]; // 调用地址
                            let target = allEvents[i][2];   // 目标地址
                            let depth = allEvents[i][3];    // depth
                            let description = '';
                            let space_num = '';
                            if (target.compare(base_addr) >= 0 && target.compare(base_addr.add(base_size)) < 0) {
                                if (is_first) {
                                    is_first = false;
                                    first_depth = depth;
                                }
                                let location_description = ' [' + ptr(location).sub(base_addr) + '] ';
                                let target_description = ' [' + ptr(target).sub(base_addr) + ']';
                                let length = (depth - first_depth);
                                for (let j = 0; j < length; j++) {
                                    space_num = space_num + ' ';
                                }
                                description = space_num + target_description + '(' + location_description + ')' + ' -- ' + length;
                                console.log(description); 
                            } 
                        }
                    }
                }
            })
        }, onLeave: function(retval) {
            Stalker.unfollow(this.tid);
        }
    })
}