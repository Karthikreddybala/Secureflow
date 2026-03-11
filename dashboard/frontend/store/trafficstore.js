import create from 'zustand';

export const useTrafficStore = create((set) => ({
    flows: [],
    addflow: (flow) => set((state) => ({ flows: [...state.flows, flow] })),
    clearTrafficData: () => set({ flows: [] }),
}));