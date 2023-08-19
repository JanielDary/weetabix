## From Dead Data to Digestion: Extracting Windows Fibers for your digital forensics diet

### https://www.blackhat.com/us-23/briefings/schedule/#from-dead-data-to-digestion-extracting-windows-fibers-for-your-digital-forensics-diet-32832

### Speakers

Daniel Jary

### BlackHat Abstract

Windows Fibers are a lesser known optional component of Windows. They are being adopted by attackers as a non-traditional way to execute code and sidestep EDR telemetry sources. Not only this but Fibers are being used by C2 frameworks as a vehicle to implement other techniques such as thread stack spoofing. Alarmingly there is no open-source tooling or standard APIs that can remotely and comprehensively enumerate and detect malicious Fiber use from memory.
This talk will take you on a journey on how to reverse the underlying API, understand the core components of the undocumented internals of Fibers, and then use this knowledge to create granular detection telemetry from process memory. It will conclude by demonstrating and then open-sourcing a novel tool called Weetabix that automates this whole process for the benefit of threat hunting teams or EDR developers.