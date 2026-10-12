import type { Env as WorkerEnv } from "../src/group";

declare global {
  namespace Cloudflare {
    interface Env extends WorkerEnv {
      /** Tests only: public half of the throwaway FCM service-account key. */
      TEST_FCM_PUBLIC_KEY: string;
      /** Tests only: fuzz inputs per decoder ("" = default). */
      FUZZ_N: string;
    }
    interface GlobalProps {
      mainModule: typeof import("../src/index");
      durableNamespaces: "GroupDO";
    }
  }
}
