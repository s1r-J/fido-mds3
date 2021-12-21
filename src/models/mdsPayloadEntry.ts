import dayjs from 'dayjs';
import {
  FM3AuthenticatorStatus,
  FM3MetadataBLOBPayloadEntry, FM3StatusReport,
} from '../type';

class MdsPayloadEntry {

  private entry: FM3MetadataBLOBPayloadEntry;

  constructor(entryJson: any);
  constructor(entryJsonString: string);
  constructor(entry: FM3MetadataBLOBPayloadEntry);
  constructor(arg: any) {
    if (typeof arg === 'string') {
      const entry = JSON.parse(arg) as FM3MetadataBLOBPayloadEntry;
      this.entry = entry;
    } else {
      const entry = arg as FM3MetadataBLOBPayloadEntry;
      this.entry = entry;
    }
  }

  getPayloadEntry(): FM3MetadataBLOBPayloadEntry {
    return this.entry;
  }

  getAAGUID(): string | undefined {
    return this.entry.aaguid;
  }

  getAAID(): string | undefined {
    return this.entry.aaid;
  }

  getAttestationCertificateKeyIdentifiers(): string[] | undefined {
    return this.entry.attestationCertificateKeyIdentifiers;
  }

  getLatestStatusReport(): FM3StatusReport {
    const statusReports = [ ...this.entry.statusReports];
    statusReports.sort((a, b) => {
      if (a.effectiveDate && b.effectiveDate) {
        const delta = dayjs(b.effectiveDate).unix() - dayjs(a.effectiveDate).unix();
        if (delta === 0) {
          if (a.status === 'FIDO_CERTIFIED' && b.status === 'FIDO_CERTIFIED_L1') {
            return 1;
          } else if (a.status === 'FIDO_CERTIFIED_L1' && b.status === 'FIDO_CERTIFIED') {
            return -1;
          }
        }
        return delta;
      }

      return -1;
    });

    return statusReports[0];
  }

  getLatestAuthenticatorStatus(): FM3AuthenticatorStatus {
    return this.getLatestStatusReport().status;
  }

}

export default MdsPayloadEntry;
